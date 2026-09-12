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
	"github.com/pitabwire/frame/v2/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const meterName = "service_audit"

// Metrics holds every instrument the service emits (spec §15).
type Metrics struct {
	IntakeAccepted       telemetry.Counter
	IntakeRejected       telemetry.Counter
	IntakeBacklog        telemetry.Gauge
	IntakeOldestAge      telemetry.FloatGauge
	IntakeFailed         telemetry.Gauge
	CommitLatency        telemetry.Histogram
	WriterBatchSize      telemetry.Histogram
	WriterTickDuration   telemetry.Histogram
	WriterCASConflicts   telemetry.Counter
	CheckpointAge        telemetry.FloatGauge
	SigningKeyActive     telemetry.Gauge
	VerificationRuns     telemetry.Counter
	VerificationFailures telemetry.Counter
	ExportEntries        telemetry.Counter
}

// NewMetrics registers the instruments on the global meter provider.
func NewMetrics() *Metrics {
	bm := telemetry.NewBusinessMetrics(meterName)
	return &Metrics{
		IntakeAccepted:       bm.Counter("audit_intake_accepted_total", "Entries accepted into intake"),
		IntakeRejected:       bm.Counter("audit_intake_rejected_total", "Entries rejected by the validator"),
		IntakeBacklog:        bm.Gauge("audit_intake_backlog", "Accepted entries not yet chained, per tenant"),
		IntakeOldestAge:      bm.FloatGauge("audit_intake_oldest_age_seconds", "Age of the oldest accepted entry"),
		IntakeFailed:         bm.Gauge("audit_intake_failed", "Intake rows in FAILED state"),
		CommitLatency:        bm.Histogram("audit_commit_latency_seconds", "Receipt to chain commit latency"),
		WriterBatchSize:      bm.Histogram("audit_writer_batch_size", "Entries committed per batch"),
		WriterTickDuration:   bm.Histogram("audit_writer_tick_duration_seconds", "Writer tick wall time"),
		WriterCASConflicts:   bm.Counter("audit_writer_cas_conflicts_total", "Head compare-and-swap conflicts"),
		CheckpointAge:        bm.FloatGauge("audit_checkpoint_age_seconds", "Age of the latest checkpoint, per tenant"),
		SigningKeyActive:     bm.Gauge("audit_signing_key_active_info", "Active signing key (1) with key_id and retired attributes"),
		VerificationRuns:     bm.Counter("audit_verification_runs_total", "VerifyIntegrity calls"),
		VerificationFailures: bm.Counter("audit_verification_failures_total", "VerifyIntegrity calls that found a break"),
		ExportEntries:        bm.Counter("audit_export_entries_total", "Entries streamed by ExportAuditEntries"),
	}
}

// Attribute keys shared across instruments.
var (
	attrService = attribute.Key("service")
	attrReason  = attribute.Key("reason")
	attrTenant  = attribute.Key("tenant_id")
	attrOutcome = attribute.Key("outcome")
	attrKeyID   = attribute.Key("key_id")
	attrRetired = attribute.Key("retired")
)

func tracer() trace.Tracer { return otel.Tracer(meterName) }
