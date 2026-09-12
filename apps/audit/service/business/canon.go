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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/pitabwire/frame/v2/data"
)

// Canonical encoding version 2.
//
// canon_v2(entry) is the concatenation, over the fixed field order below, of
// uvarint(len(field)) ‖ field. Integers are decimal ASCII, times are RFC 3339
// UTC with microseconds, absent optional fields are length 0, and JSON
// values use CanonicalJSON (sorted keys, no whitespace, no HTML escaping).
//
// The encoder is mirrored byte-for-byte in common/auditverify so bundles can
// be verified without this service. Any change here is a new canon version.

const canonTimeLayout = "2006-01-02T15:04:05.000000Z"

// CanonicalV2 returns the canon_v2 bytes of an entry (previous hash excluded).
func CanonicalV2(e *models.AuditEntry) []byte {
	var buf bytes.Buffer
	w := func(s string) {
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], uint64(len(s)))
		buf.Write(tmp[:n])
		buf.WriteString(s)
	}
	relations, _ := CanonicalJSON(e.Relations)
	details, _ := CanonicalJSON(e.Details)

	w(strconv.Itoa(int(e.CanonVersion)))
	w(e.TenantID)
	w(e.PartitionID)
	w(strconv.FormatInt(e.Seq, 10))
	w(e.EntryID)
	w(e.Service)
	w(strconv.Itoa(int(e.ManifestVersion)))
	w(e.ProfileID)
	w(e.OnBehalfOf)
	w(e.ActorServiceAccountID)
	w(e.Action)
	w(e.ResourceType)
	w(e.ResourceID)
	w(strconv.FormatInt(e.ResourceVersion, 10))
	w(e.StateFrom)
	w(e.StateTo)
	w(e.TargetProfileID)
	w(e.DeviceID)
	w(e.DeviceKeyID)
	w(e.IPAddress)
	w(e.UserAgent)
	w(e.TraceID)
	w(e.CorrelationID)
	w(e.EventID)
	w(e.IntentID)
	w(e.InstanceID)
	w(e.PayloadHash)
	w(e.AuthorizationHash)
	w(e.PolicyHash)
	w(canonTime(e.OccurredAt))
	w(canonTime(e.ReceivedAt))
	w(canonTime(e.CreatedAt))
	w(string(relations))
	w(string(details))
	return buf.Bytes()
}

func canonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(canonTimeLayout)
}

// CanonicalJSON encodes v deterministically: object keys sorted by their
// UTF-8 bytes, no insignificant whitespace, no HTML escaping, integers
// without exponent, other floats in shortest round-trip form. nil encodes as
// "null". Non-finite floats are an error.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeJSONString(buf, x)
	case json.Number:
		buf.WriteString(x.String())
	case float64:
		return writeFloat(buf, x)
	case float32:
		return writeFloat(buf, float64(x))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		writeInteger(buf, x)
	case map[string]any:
		return writeObject(buf, x)
	case data.JSONMap:
		return writeObject(buf, map[string]any(x))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// Fall back through encoding/json for structs, typed maps and slices,
		// then re-canonicalise the generic form.
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var generic any
		if err = dec.Decode(&generic); err != nil {
			return err
		}
		return writeCanonical(buf, generic)
	}
	return nil
}

func writeInteger(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	}
}

func writeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonical(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical json: non-finite number %v", f)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

func writeJSONString(buf *bytes.Buffer, s string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	// Encoder appends a newline; drop it.
	buf.Truncate(buf.Len() - 1)
	return nil
}

// EntryHashV2 is hex(SHA-256(canon_v2(entry) ‖ previous_hash_bytes)) where
// previous_hash_bytes is the raw 32-byte decode of the previous hex hash, or
// empty for genesis.
func EntryHashV2(e *models.AuditEntry, previousHash string) string {
	h := sha256.New()
	h.Write(CanonicalV2(e))
	if prev, err := hex.DecodeString(previousHash); err == nil {
		h.Write(prev)
	} else {
		h.Write([]byte(previousHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EntryHashV1 reproduces the pre-v2 pipe-delimited pre-image. It is used only
// to verify entries with CanonVersion == 1 and must never change.
func EntryHashV1(e *models.AuditEntry, previousHash string) string {
	detailsJSON, _ := json.Marshal(e.Details)
	createdAt := ""
	if !e.CreatedAt.IsZero() {
		createdAt = e.CreatedAt.UTC().Format(canonTimeLayout)
	}
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.ProfileID, e.Action, e.ResourceType, e.ResourceID, e.Service,
		string(detailsJSON), e.IPAddress, e.UserAgent, e.DeviceID,
		e.TargetProfileID, e.TraceID, createdAt, previousHash)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// EntryHash dispatches on the entry's CanonVersion.
func EntryHash(e *models.AuditEntry, previousHash string) (string, error) {
	switch e.CanonVersion {
	case models.CanonVersionLegacy:
		return EntryHashV1(e, previousHash), nil
	case models.CanonVersionV2:
		return EntryHashV2(e, previousHash), nil
	default:
		return "", fmt.Errorf("unsupported canon_version %d", e.CanonVersion)
	}
}

// CheckpointHash is hex(SHA-256("chk" ‖ tenant ‖ seq ‖ entry_hash ‖ created_at))
// with the same length-prefix rule as canon_v2.
func CheckpointHash(tenantID string, seq int64, entryHash string, createdAt time.Time) string {
	var buf bytes.Buffer
	for _, s := range []string{"chk", tenantID, strconv.FormatInt(seq, 10), entryHash, canonTime(createdAt)} {
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], uint64(len(s)))
		buf.Write(tmp[:n])
		buf.WriteString(s)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}
