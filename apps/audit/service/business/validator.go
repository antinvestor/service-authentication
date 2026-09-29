// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/util"
)

// Rejection reasons recorded in audit_rejections and metrics.
const (
	ReasonSchema           = "schema"
	ReasonActor            = "actor"
	ReasonServiceBinding   = "service_binding"
	ReasonVocabulary       = "vocabulary"
	ReasonSize             = "size"
	ReasonForbiddenContent = "forbidden_content"
	ReasonTime             = "time"
	ReasonHash             = "hash"
	// ReasonLinking covers the K11 request/outcome rules (GFOS §10.4).
	ReasonLinking = "linking"
)

// Validation limits (spec §6.2).
const (
	MaxDetailsBytes   = 16 * 1024
	MaxStringBytes    = 512
	MaxUserAgentBytes = 1024
	MaxBatch          = 100
	TimeWindow        = 5 * time.Minute
	FutureSkew        = 30 * time.Second
	// BackdatingWindow bounds occurred_at for manifests that allow replay.
	BackdatingWindow = 400 * 24 * time.Hour
)

// ClassRequired is the producer audit class whose outcomes must link back to
// their REQUESTED entry (GFOS §10.4).
const ClassRequired = "AUDIT_REQUIRED"

// Detail keys the K11 fields travel under. They are the keys the shared
// common/audit client already writes (class.go) plus the degradation marker,
// and the validator mirrors the typed request fields into them so the
// canonical pre-image — which covers details — binds the phase, the link and
// the marking without a new canonical version.
const (
	DetailKeyPhase    = "phase"
	DetailKeyLinked   = "linked_entry_id"
	DetailKeyClass    = "class"
	DetailKeyEntryID  = "entry_id"
	DetailKeyOccurred = "occurred_at"
	DetailKeyDegraded = "written_during_degradation"
)

// PermissionCreateAny lets the audit operator role log under any service.
const PermissionCreateAny = "audit_create_any"

// ValidationError is a boundary rejection. Reason selects the Connect code
// in the handler; Field names the offending input without echoing content.
type ValidationError struct {
	Reason string
	Field  string
	Detail string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", e.Reason, e.Field, e.Detail)
}

// Caller is the producer identity derived from JWT claims.
type Caller struct {
	TenantID         string
	PartitionID      string
	AccessID         string
	ProfileID        string
	ServiceAccountID string
	ServiceName      string
	Roles            []string
	// CanCreateAny is true when the caller holds audit_create_any. The
	// function-access interceptor cannot express "either permission", so the
	// handler resolves it explicitly and sets this flag.
	CanCreateAny bool
}

// CallerFromClaims reads the caller from the request context.
func CallerFromClaims(ctx context.Context) Caller {
	claims := security.ClaimsFromContext(ctx)
	if claims == nil {
		return Caller{}
	}
	c := Caller{
		TenantID: claims.GetTenantID(), PartitionID: claims.GetPartitionID(), AccessID: claims.GetAccessID(),
		ProfileID: claims.GetProfileID(), ServiceName: claims.GetServiceName(), Roles: claims.GetRoles(),
	}
	if v, ok := claims.Ext["service_account_id"].(string); ok {
		c.ServiceAccountID = strings.TrimSpace(v)
	}
	return c
}

// Manifest is the validator's view of a registered vocabulary.
type Manifest struct {
	Version            int32
	Actions            map[string]struct{}
	ResourceTypes      map[string]struct{}
	OpenVocabulary     bool
	AllowBackdating    bool
	ExtraForbiddenKeys []string
}

// ManifestLookup resolves the manifest for a service; ok=false when none.
type ManifestLookup func(ctx context.Context, service string) (*Manifest, bool, error)

// NormalisedEntry is a validated request ready for intake.
type NormalisedEntry struct {
	Entry *models.AuditEntry
}

// Validator applies the boundary rules.
type Validator struct {
	lookup          ManifestLookup
	requireManifest bool
	degradedWindow  time.Duration
}

// NewValidator creates a validator over the manifest registry. degradedWindow
// bounds how far back an entry marked as written during AUDIT_DEGRADED may be
// backdated when it is drained from a producer outbox (GFOS §10.4, K11).
func NewValidator(lookup ManifestLookup, requireManifest bool, degradedWindow time.Duration) *Validator {
	if degradedWindow <= 0 {
		degradedWindow = DefaultDegradedWindow
	}
	return &Validator{lookup: lookup, requireManifest: requireManifest, degradedWindow: degradedWindow}
}

// DefaultDegradedWindow is used when configuration leaves it unset.
const DefaultDegradedWindow = 168 * time.Hour

var (
	forbiddenKeyPattern = regexp.MustCompile(`(?i)(password|secret|token|authorization|cookie|private_key|otp|\bpin\b|^pin$|_pin$|^pin_)`)
	msisdnPattern       = regexp.MustCompile(`^\+?[0-9]{9,15}$`)
	cardPattern         = regexp.MustCompile(`^[0-9]{13,19}$`)
	hexHashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Validate checks req from caller at time now and returns the normalised
// entry or a ValidationError. Schema constraints (buf.validate) are enforced
// by the Connect validation interceptor before this runs.
func (v *Validator) Validate(ctx context.Context, caller Caller, req *auditv1.CreateAuditEntryRequest, now time.Time) (*NormalisedEntry, *ValidationError) {
	if req == nil {
		return nil, &ValidationError{Reason: ReasonSchema, Detail: "request is required"}
	}
	// Postgres keeps microseconds; normalise so hashes cover stored values.
	now = now.UTC().Truncate(time.Microsecond)
	if caller.TenantID == "" || caller.ProfileID == "" {
		return nil, &ValidationError{Reason: ReasonActor, Field: "caller", Detail: "authenticated tenant and profile are required"}
	}

	profileID, onBehalfOf, service, verr := v.checkIdentity(caller, req)
	if verr != nil {
		return nil, verr
	}

	// Sizes.
	if serr := checkSizes(req); serr != nil {
		return nil, serr
	}

	manifest, unmanifested, verr := v.checkVocabulary(ctx, service, req)
	if verr != nil {
		return nil, verr
	}

	// Forbidden content.
	var details data.JSONMap
	if req.GetDetails() != nil {
		details = req.GetDetails().AsMap()
	}
	var extra []string
	if manifest != nil {
		extra = manifest.ExtraForbiddenKeys
	}
	if ferr := checkForbidden(details, extra); ferr != nil {
		return nil, ferr
	}

	link, verr := resolveLinking(req, details)
	if verr != nil {
		return nil, verr
	}

	occurredAt, verr := v.checkTime(req, details, manifest, link.Degraded, now)
	if verr != nil {
		return nil, verr
	}
	if verr = checkHashes(req); verr != nil {
		return nil, verr
	}

	details = mirrorLinking(details, link)

	entryID := strings.TrimSpace(req.GetEntryId())
	if entryID == "" {
		// Compatibility bridge: the GFOS pkg/auditclass recorder carries its
		// idempotency key in details["entry_id"] only. Promoting it makes a
		// drained outbox replay idempotent instead of duplicating the entry.
		entryID = detailString(details, DetailKeyEntryID)
	}
	if len(entryID) > MaxStringBytes {
		return nil, &ValidationError{Reason: ReasonSize, Field: "entry_id", Detail: fmt.Sprintf("exceeds %d bytes", MaxStringBytes)}
	}
	if entryID == "" {
		entryID = util.IDString()
	}

	e := &models.AuditEntry{
		ProfileID: profileID, Action: req.GetAction(), ResourceType: req.GetResourceType(), ResourceID: req.GetResourceId(),
		Service: service, Details: details, IPAddress: req.GetIpAddress(), UserAgent: req.GetUserAgent(),
		DeviceID: req.GetDeviceId(), TargetProfileID: req.GetTargetProfileId(), TraceID: req.GetTraceId(),
		EntryID: entryID, ActorServiceAccountID: caller.ServiceAccountID, OnBehalfOf: onBehalfOf,
		OccurredAt: occurredAt, ReceivedAt: now, Unmanifested: unmanifested,
		CorrelationID: req.GetCorrelationId(), EventID: req.GetEventId(), IntentID: req.GetIntentId(), InstanceID: req.GetInstanceId(),
		PayloadHash: req.GetPayloadHash(), AuthorizationHash: req.GetAuthorizationHash(), PolicyHash: req.GetPolicyHash(),
		DeviceKeyID: req.GetDeviceKeyId(), StateFrom: req.GetStateFrom(), StateTo: req.GetStateTo(),
		ResourceVersion: req.GetResourceVersion(), CanonVersion: models.CanonVersionCurrent,
		Phase: link.Phase, OutcomeOfEntryID: link.OutcomeOf, AuditClass: link.Class,
		WrittenDuringDegradation: link.Degraded,
	}
	e.TenantID, e.PartitionID, e.AccessID = caller.TenantID, caller.PartitionID, caller.AccessID
	if manifest != nil {
		e.ManifestVersion = manifest.Version
	}
	if rels := req.GetRelations(); len(rels) > 0 {
		items := make([]any, 0, len(rels))
		for _, r := range rels {
			items = append(items, map[string]any{
				"parent_type": r.GetParentType(), "parent_id": r.GetParentId(),
				"child_type": r.GetChildType(), "child_id": r.GetChildId(), "action": r.GetAction(),
			})
		}
		e.Relations = data.JSONMap{"items": items}
	}
	return &NormalisedEntry{Entry: e}, nil
}

// checkVocabulary resolves the producer's manifest and holds the entry to
// the vocabulary it registered. A service with no manifest is accepted and
// flagged unmanifested until AUDIT_REQUIRE_MANIFEST is on.
func (v *Validator) checkVocabulary(ctx context.Context, service string,
	req *auditv1.CreateAuditEntryRequest) (*Manifest, bool, *ValidationError) {
	var manifest *Manifest
	unmanifested := true
	if v.lookup != nil {
		m, ok, err := v.lookup(ctx, service)
		if err != nil {
			util.Log(ctx).WithError(err).WithField("service", service).Warn("manifest lookup failed; treating as unmanifested")
		} else if ok {
			manifest, unmanifested = m, false
		}
	}
	if unmanifested && v.requireManifest {
		return nil, true, &ValidationError{Reason: ReasonVocabulary, Field: "service", Detail: "no audit manifest registered"}
	}
	if manifest != nil && !manifest.OpenVocabulary {
		if _, ok := manifest.Actions[req.GetAction()]; !ok {
			return nil, unmanifested, &ValidationError{Reason: ReasonVocabulary, Field: "action", Detail: "unknown action " + req.GetAction()}
		}
		if _, ok := manifest.ResourceTypes[req.GetResourceType()]; !ok {
			return nil, unmanifested, &ValidationError{Reason: ReasonVocabulary, Field: "resource_type",
				Detail: "unknown resource_type " + req.GetResourceType()}
		}
	}
	return manifest, unmanifested, nil
}

// checkIdentity applies the actor rule and the service binding.
func (v *Validator) checkIdentity(caller Caller, req *auditv1.CreateAuditEntryRequest) (profileID, onBehalfOf, service string, verr *ValidationError) {
	// Actor rule: profile_id must be a person. A service-account caller may
	// only log with on_behalf_of set, and then profile_id is the person.
	profileID = strings.TrimSpace(req.GetProfileId())
	onBehalfOf = strings.TrimSpace(req.GetOnBehalfOf())
	if profileID == "" {
		return "", "", "", &ValidationError{Reason: ReasonActor, Field: "profile_id", Detail: "a person is required"}
	}
	if caller.ServiceAccountID != "" && onBehalfOf == "" && profileID == caller.ProfileID {
		return "", "", "", &ValidationError{Reason: ReasonActor, Field: "profile_id",
			Detail: "service accounts are not audited; set on_behalf_of to record an operator acting for a person"}
	}
	service = strings.TrimSpace(req.GetService())
	if !caller.CanCreateAny && (caller.ServiceName == "" || service != caller.ServiceName) {
		return "", "", "", &ValidationError{Reason: ReasonServiceBinding, Field: "service",
			Detail: fmt.Sprintf("caller %q may not log as %q", caller.ServiceName, service)}
	}
	return profileID, onBehalfOf, service, nil
}

// linking is the resolved K11 request/outcome state of one request.
type linking struct {
	Phase     string
	OutcomeOf string
	Class     string
	Degraded  bool
}

// resolveLinking reads the K11 fields, falling back to the detail keys the
// GFOS pkg/auditclass recorder sends today ("phase", "linked_entry_id",
// "class"), and applies the §10.4 rules: a REQUESTED entry never names an
// outcome, and an outcome of an AUDIT_REQUIRED command must name its request.
func resolveLinking(req *auditv1.CreateAuditEntryRequest, details data.JSONMap) (linking, *ValidationError) {
	l := linking{
		Phase:     phaseName(req.GetPhase()),
		OutcomeOf: strings.TrimSpace(req.GetOutcomeOfEntryId()),
		Class:     strings.TrimSpace(req.GetAuditClass()),
		Degraded:  req.GetWrittenDuringDegradation(),
	}
	if l.Phase == "" {
		l.Phase = normalisePhase(detailString(details, DetailKeyPhase))
	}
	if l.OutcomeOf == "" {
		l.OutcomeOf = detailString(details, DetailKeyLinked)
	}
	if l.Class == "" {
		l.Class = detailString(details, DetailKeyClass)
	}
	if !l.Degraded {
		l.Degraded, _ = details[DetailKeyDegraded].(bool)
	}
	if l.Phase != "" && l.Phase != models.PhaseRequested && l.Phase != models.PhaseCompleted && l.Phase != models.PhaseFailed {
		return linking{}, &ValidationError{Reason: ReasonLinking, Field: "phase", Detail: "unknown phase " + l.Phase}
	}
	if len(l.OutcomeOf) > MaxStringBytes {
		return linking{}, &ValidationError{Reason: ReasonSize, Field: "outcome_of_entry_id", Detail: fmt.Sprintf("exceeds %d bytes", MaxStringBytes)}
	}
	if l.Phase == models.PhaseRequested && l.OutcomeOf != "" {
		return linking{}, &ValidationError{Reason: ReasonLinking, Field: "outcome_of_entry_id",
			Detail: "a REQUESTED entry is the request, not an outcome"}
	}
	isOutcome := l.Phase == models.PhaseCompleted || l.Phase == models.PhaseFailed
	if isOutcome && l.Class == ClassRequired && l.OutcomeOf == "" {
		return linking{}, &ValidationError{Reason: ReasonLinking, Field: "outcome_of_entry_id",
			Detail: "an outcome of an AUDIT_REQUIRED command must reference its REQUESTED entry"}
	}
	if l.OutcomeOf != "" && l.OutcomeOf == strings.TrimSpace(req.GetEntryId()) {
		return linking{}, &ValidationError{Reason: ReasonLinking, Field: "outcome_of_entry_id",
			Detail: "an entry cannot be its own outcome"}
	}
	if l.Degraded && l.Phase == "" {
		return linking{}, &ValidationError{Reason: ReasonLinking, Field: "phase",
			Detail: "an entry written during degradation must carry its phase"}
	}
	return l, nil
}

// mirrorLinking writes the resolved K11 fields back into details so the
// signed pre-image covers them. A producer that already sent them in details
// sees no change; a producer that used the typed fields gets them recorded in
// the one place the canonical encoding hashes.
func mirrorLinking(details data.JSONMap, l linking) data.JSONMap {
	if l.Phase == "" && l.OutcomeOf == "" && l.Class == "" && !l.Degraded {
		return details
	}
	if details == nil {
		details = data.JSONMap{}
	}
	if l.Phase != "" {
		details[DetailKeyPhase] = l.Phase
	}
	if l.OutcomeOf != "" {
		details[DetailKeyLinked] = l.OutcomeOf
	}
	if l.Class != "" {
		details[DetailKeyClass] = l.Class
	}
	if l.Degraded {
		details[DetailKeyDegraded] = true
	}
	return details
}

func phaseName(p auditv1.AuditPhase) string {
	switch p {
	case auditv1.AuditPhase_AUDIT_PHASE_REQUESTED:
		return models.PhaseRequested
	case auditv1.AuditPhase_AUDIT_PHASE_COMPLETED:
		return models.PhaseCompleted
	case auditv1.AuditPhase_AUDIT_PHASE_FAILED:
		return models.PhaseFailed
	case auditv1.AuditPhase_AUDIT_PHASE_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func normalisePhase(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func detailString(details data.JSONMap, key string) string {
	if details == nil {
		return ""
	}
	s, _ := details[key].(string)
	return strings.TrimSpace(s)
}

// checkTime bounds occurred_at. The producer may send it as the typed field
// or, on the pre-K11 client, only as details["occurred_at"]; both are subject
// to the same rules. An entry marked as written during AUDIT_DEGRADED, or a
// producer whose manifest allows backdating, may carry an older time so a
// drained outbox keeps the time the human acted.
func (v *Validator) checkTime(req *auditv1.CreateAuditEntryRequest, details data.JSONMap, manifest *Manifest,
	degraded bool, now time.Time) (time.Time, *ValidationError) {
	occurredAt := time.Time{}
	field := "occurred_at"
	switch {
	case req.GetOccurredAt() != nil:
		occurredAt = req.GetOccurredAt().AsTime()
	default:
		if raw := detailString(details, DetailKeyOccurred); raw != "" {
			field = "details.occurred_at"
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return time.Time{}, &ValidationError{Reason: ReasonTime, Field: field, Detail: "not RFC 3339"}
			}
			occurredAt = parsed
		}
	}
	if occurredAt.IsZero() {
		return now, nil
	}
	occurredAt = occurredAt.UTC().Truncate(time.Microsecond)
	if occurredAt.After(now.Add(FutureSkew)) {
		return time.Time{}, &ValidationError{Reason: ReasonTime, Field: field, Detail: "in the future"}
	}
	window := TimeWindow
	if degraded {
		window = v.degradedWindow
	}
	if manifest != nil && manifest.AllowBackdating && BackdatingWindow > window {
		window = BackdatingWindow
	}
	if occurredAt.Before(now.Add(-window)) {
		return time.Time{}, &ValidationError{Reason: ReasonTime, Field: field, Detail: "older than the accepted window"}
	}
	return occurredAt, nil
}

func checkHashes(req *auditv1.CreateAuditEntryRequest) *ValidationError {
	for name, val := range map[string]string{
		"payload_hash": req.GetPayloadHash(), "authorization_hash": req.GetAuthorizationHash(), "policy_hash": req.GetPolicyHash(),
	} {
		if val != "" && !hexHashPattern.MatchString(val) {
			return &ValidationError{Reason: ReasonHash, Field: name, Detail: "must be 32-byte lowercase hex"}
		}
	}
	return nil
}

func checkSizes(req *auditv1.CreateAuditEntryRequest) *ValidationError {
	strs := map[string]string{
		"profile_id": req.GetProfileId(), "action": req.GetAction(), "resource_type": req.GetResourceType(),
		"resource_id": req.GetResourceId(), "service": req.GetService(), "ip_address": req.GetIpAddress(),
		"device_id": req.GetDeviceId(), "target_profile_id": req.GetTargetProfileId(), "trace_id": req.GetTraceId(),
		"entry_id": req.GetEntryId(), "on_behalf_of": req.GetOnBehalfOf(), "correlation_id": req.GetCorrelationId(),
		"event_id": req.GetEventId(), "intent_id": req.GetIntentId(), "instance_id": req.GetInstanceId(),
		"device_key_id": req.GetDeviceKeyId(), "state_from": req.GetStateFrom(), "state_to": req.GetStateTo(),
	}
	for f, s := range strs {
		if len(s) > MaxStringBytes {
			return &ValidationError{Reason: ReasonSize, Field: f, Detail: fmt.Sprintf("exceeds %d bytes", MaxStringBytes)}
		}
	}
	if len(req.GetUserAgent()) > MaxUserAgentBytes {
		return &ValidationError{Reason: ReasonSize, Field: "user_agent", Detail: fmt.Sprintf("exceeds %d bytes", MaxUserAgentBytes)}
	}
	if req.GetDetails() != nil {
		raw, err := json.Marshal(req.GetDetails().AsMap())
		if err != nil {
			return &ValidationError{Reason: ReasonSchema, Field: "details", Detail: "not serialisable"}
		}
		if len(raw) > MaxDetailsBytes {
			return &ValidationError{Reason: ReasonSize, Field: "details", Detail: fmt.Sprintf("exceeds %d bytes", MaxDetailsBytes)}
		}
	}
	return nil
}

// checkForbidden walks details recursively. Keys are matched against the
// built-in pattern and manifest extras; string values are matched against
// MSISDN and card-number shapes. Only the key path is reported.
func checkForbidden(details map[string]any, extraKeys []string) *ValidationError {
	var walk func(path string, v any) *ValidationError
	walk = func(path string, v any) *ValidationError {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				p := k
				if path != "" {
					p = path + "." + k
				}
				if forbiddenKeyPattern.MatchString(k) || matchesExtra(k, extraKeys) {
					return &ValidationError{Reason: ReasonForbiddenContent, Field: "details." + p, Detail: "forbidden key"}
				}
				if verr := walk(p, val); verr != nil {
					return verr
				}
			}
		case []any:
			for i, item := range x {
				if verr := walk(fmt.Sprintf("%s[%d]", path, i), item); verr != nil {
					return verr
				}
			}
		case string:
			s := strings.ReplaceAll(strings.ReplaceAll(x, " ", ""), "-", "")
			if msisdnPattern.MatchString(s) || (cardPattern.MatchString(s) && luhnValid(s)) {
				return &ValidationError{Reason: ReasonForbiddenContent, Field: "details." + path, Detail: "value looks like a phone or card number"}
			}
		}
		return nil
	}
	return walk("", map[string]any(details))
}

func matchesExtra(key string, extra []string) bool {
	lk := strings.ToLower(key)
	for _, e := range extra {
		if e != "" && strings.Contains(lk, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

func luhnValid(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
