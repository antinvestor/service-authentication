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

package business_test

import (
	"context"
	"strings"
	"testing"
	"time"

	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func userCaller() business.Caller {
	return business.Caller{TenantID: "t1", PartitionID: "p1", ProfileID: "person-1", ServiceName: "service_loans"}
}

func saCaller() business.Caller {
	c := userCaller()
	c.ProfileID = "sa-profile"
	c.ServiceAccountID = "sa-1"
	return c
}

func validRequest() *auditv1.CreateAuditEntryRequest {
	req := &auditv1.CreateAuditEntryRequest{}
	req.SetProfileId("person-1")
	req.SetAction("create")
	req.SetResourceType("loan")
	req.SetResourceId("loan-1")
	req.SetService("service_loans")
	return req
}

func withDetails(req *auditv1.CreateAuditEntryRequest, m map[string]any) {
	s, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}
	req.SetDetails(s)
}

func fixedLookup(m *business.Manifest) business.ManifestLookup {
	return func(_ context.Context, _ string) (*business.Manifest, bool, error) { return m, m != nil, nil }
}

func TestValidator_Rules(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	strict := &business.Manifest{Version: 3,
		Actions: map[string]struct{}{"create": {}}, ResourceTypes: map[string]struct{}{"loan": {}},
		ExtraForbiddenKeys: []string{"national_id"}}
	backdating := &business.Manifest{Version: 1, OpenVocabulary: true, AllowBackdating: true}

	cases := []struct {
		name       string
		caller     business.Caller
		manifest   *business.Manifest
		require    bool
		mutate     func(*auditv1.CreateAuditEntryRequest)
		wantReason string
		wantField  string
	}{
		{name: "happy path user", caller: userCaller(), manifest: strict},
		{name: "unmanifested accepted and flagged", caller: userCaller()},
		{name: "require manifest rejects unmanifested", caller: userCaller(), require: true, wantReason: business.ReasonVocabulary, wantField: "service"},
		{name: "unauthenticated", caller: business.Caller{}, wantReason: business.ReasonActor, wantField: "caller"},
		{name: "empty person", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetProfileId("  ") }, wantReason: business.ReasonActor, wantField: "profile_id"},
		{name: "service account without on_behalf_of", caller: saCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetProfileId("sa-profile") }, wantReason: business.ReasonActor, wantField: "profile_id"},
		{name: "service account acting for a person", caller: saCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetProfileId("person-9"); r.SetOnBehalfOf("person-9") }},
		{name: "service binding mismatch", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetService("service_other") }, wantReason: business.ReasonServiceBinding, wantField: "service"},
		{name: "create_any overrides binding", caller: func() business.Caller { c := userCaller(); c.CanCreateAny = true; return c }(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetService("service_other") }},
		{name: "unknown action", caller: userCaller(), manifest: strict, mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetAction("explode") }, wantReason: business.ReasonVocabulary, wantField: "action"},
		{name: "unknown resource type", caller: userCaller(), manifest: strict, mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetResourceType("rocket") }, wantReason: business.ReasonVocabulary, wantField: "resource_type"},
		{name: "open vocabulary accepts anything", caller: userCaller(), manifest: backdating, mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetAction("anything") }},
		{name: "string too long", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetResourceId(strings.Repeat("x", 513)) }, wantReason: business.ReasonSize, wantField: "resource_id"},
		{name: "user agent too long", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetUserAgent(strings.Repeat("u", 1025)) }, wantReason: business.ReasonSize, wantField: "user_agent"},
		{name: "details too large", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) {
			withDetails(r, map[string]any{"blob": strings.Repeat("d", 17*1024)})
		}, wantReason: business.ReasonSize, wantField: "details"},
		{name: "forbidden key password", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"Password": "x"}) }, wantReason: business.ReasonForbiddenContent, wantField: "details.Password"},
		{name: "forbidden nested key token", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) {
			withDetails(r, map[string]any{"auth": map[string]any{"access_token": "x"}})
		}, wantReason: business.ReasonForbiddenContent, wantField: "details.auth.access_token"},
		{name: "forbidden manifest extra key", caller: userCaller(), manifest: strict, mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"National_ID": "x"}) }, wantReason: business.ReasonForbiddenContent, wantField: "details.National_ID"},
		{name: "msisdn value", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"contact": "+254712345678"}) }, wantReason: business.ReasonForbiddenContent, wantField: "details.contact"},
		{name: "luhn valid card value", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"ref": "4111 1111 1111 1111"}) }, wantReason: business.ReasonForbiddenContent, wantField: "details.ref"},
		{name: "long digit run failing luhn is allowed", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"ref": "4111111111111112"}) }},
		{name: "short id number is allowed", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { withDetails(r, map[string]any{"ref": "12345678"}) }},
		{name: "value in array", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) {
			withDetails(r, map[string]any{"list": []any{"ok", "0712345678"}})
		}, wantReason: business.ReasonForbiddenContent, wantField: "details.list[1]"},
		{name: "occurred_at in future", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetOccurredAt(timestamppb.New(now.Add(31 * time.Second))) }, wantReason: business.ReasonTime, wantField: "occurred_at"},
		{name: "occurred_at slightly future ok", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetOccurredAt(timestamppb.New(now.Add(29 * time.Second))) }},
		{name: "occurred_at too old", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetOccurredAt(timestamppb.New(now.Add(-6 * time.Minute))) }, wantReason: business.ReasonTime, wantField: "occurred_at"},
		{name: "occurred_at within window", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetOccurredAt(timestamppb.New(now.Add(-4 * time.Minute))) }},
		{name: "backdating allowed by manifest", caller: userCaller(), manifest: backdating, mutate: func(r *auditv1.CreateAuditEntryRequest) {
			r.SetOccurredAt(timestamppb.New(now.Add(-30 * 24 * time.Hour)))
		}},
		{name: "bad hash", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetPayloadHash("ABCD") }, wantReason: business.ReasonHash, wantField: "payload_hash"},
		{name: "good hash", caller: userCaller(), mutate: func(r *auditv1.CreateAuditEntryRequest) { r.SetPayloadHash(strings.Repeat("ab", 32)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := business.NewValidator(fixedLookup(tc.manifest), tc.require)
			req := validRequest()
			if tc.mutate != nil {
				tc.mutate(req)
			}
			got, verr := v.Validate(context.Background(), tc.caller, req, now)
			if tc.wantReason == "" {
				require.Nil(t, verr, "expected acceptance, got %v", verr)
				require.NotNil(t, got)
				require.Equal(t, "t1", got.Entry.TenantID)
				require.NotEmpty(t, got.Entry.EntryID, "entry_id is generated when absent")
				require.Equal(t, now, got.Entry.ReceivedAt)
				if tc.manifest == nil {
					require.True(t, got.Entry.Unmanifested)
				} else {
					require.False(t, got.Entry.Unmanifested)
					require.Equal(t, tc.manifest.Version, got.Entry.ManifestVersion)
				}
				return
			}
			require.NotNil(t, verr, "expected rejection %s", tc.wantReason)
			require.Equal(t, tc.wantReason, verr.Reason)
			require.Equal(t, tc.wantField, verr.Field)
			require.Nil(t, got)
		})
	}
}

func TestValidator_PreservesProducerFields(t *testing.T) {
	now := time.Now().UTC()
	v := business.NewValidator(nil, false)
	req := validRequest()
	req.SetEntryId("e-42")
	req.SetIntentId("intent-1")
	req.SetStateFrom("A")
	req.SetStateTo("B")
	req.SetResourceVersion(7)
	rel := &auditv1.AuditRelation{}
	rel.SetParentType("profile")
	rel.SetParentId("p")
	rel.SetChildType("contact")
	rel.SetChildId("c")
	rel.SetAction("added")
	req.SetRelations([]*auditv1.AuditRelation{rel})
	withDetails(req, map[string]any{"reason": "customer request"})

	c := saCaller()
	req.SetProfileId("person-2")
	req.SetOnBehalfOf("person-2")
	got, verr := v.Validate(context.Background(), c, req, now)
	require.Nil(t, verr)
	e := got.Entry
	require.Equal(t, "e-42", e.EntryID)
	require.Equal(t, "sa-1", e.ActorServiceAccountID)
	require.Equal(t, "person-2", e.OnBehalfOf)
	require.Equal(t, "intent-1", e.IntentID)
	require.Equal(t, int64(7), e.ResourceVersion)
	require.Equal(t, "customer request", e.Details["reason"])
	items := e.Relations["items"].([]any)
	require.Len(t, items, 1)
	require.Equal(t, "contact", items[0].(map[string]any)["child_type"])
}
