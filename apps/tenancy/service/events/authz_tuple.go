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

package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/pitabwire/frame/events"
	"github.com/pitabwire/frame/security"
	"github.com/pitabwire/util"
)

const (
	EventKeyAuthzTupleWrite  = "authorization.tuple.write"
	EventKeyAuthzTupleDelete = "authorization.tuple.delete"
)

// TupleData is a JSON-serializable representation of a security.RelationTuple.
type TupleData struct {
	ObjectNamespace  string `json:"object_namespace"`
	ObjectID         string `json:"object_id"`
	Relation         string `json:"relation"`
	SubjectNamespace string `json:"subject_namespace"`
	SubjectID        string `json:"subject_id"`
	SubjectRelation  string `json:"subject_relation,omitempty"`
}

// TuplePayload is the event payload carrying tuples to write or delete.
type TuplePayload struct {
	Tuples []TupleData `json:"tuples"`
}

// TuplesToPayload converts security.RelationTuples to a TuplePayload for event emission.
func TuplesToPayload(tuples []security.RelationTuple) *TuplePayload {
	data := make([]TupleData, len(tuples))
	for i, t := range tuples {
		data[i] = TupleData{
			ObjectNamespace:  t.Object.Namespace,
			ObjectID:         t.Object.ID,
			Relation:         t.Relation,
			SubjectNamespace: t.Subject.Namespace,
			SubjectID:        t.Subject.ID,
			SubjectRelation:  t.Subject.Relation,
		}
	}
	return &TuplePayload{Tuples: data}
}

// formatTuple returns a human-readable Keto tuple string for logging:
// namespace:object#relation@subject_namespace:subject_id#subject_relation
func formatTuple(t security.RelationTuple) string {
	s := fmt.Sprintf("%s:%s#%s@%s:%s",
		t.Object.Namespace, t.Object.ID, t.Relation,
		t.Subject.Namespace, t.Subject.ID)
	if t.Subject.Relation != "" {
		s += "#" + t.Subject.Relation
	}
	return s
}

// formatTuples returns a slice of human-readable tuple strings for logging.
func formatTuples(tuples []security.RelationTuple) []string {
	out := make([]string, len(tuples))
	for i, t := range tuples {
		out[i] = formatTuple(t)
	}
	return out
}

func payloadToTuples(p *TuplePayload) []security.RelationTuple {
	tuples := make([]security.RelationTuple, len(p.Tuples))
	for i, d := range p.Tuples {
		tuples[i] = security.RelationTuple{
			Object:   security.ObjectRef{Namespace: d.ObjectNamespace, ID: d.ObjectID},
			Relation: d.Relation,
			Subject:  security.SubjectRef{Namespace: d.SubjectNamespace, ID: d.SubjectID, Relation: d.SubjectRelation},
		}
	}
	return tuples
}

// --- TupleWriteEvent ---

type TupleWriteEvent struct {
	authorizer security.Authorizer
}

func NewTupleWriteEventHandler(auth security.Authorizer) events.EventI {
	return &TupleWriteEvent{authorizer: auth}
}

func (e *TupleWriteEvent) Name() string {
	return EventKeyAuthzTupleWrite
}

func (e *TupleWriteEvent) PayloadType() any {
	return &TuplePayload{}
}

func (e *TupleWriteEvent) Validate(_ context.Context, payload any) error {
	p, ok := payload.(*TuplePayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *TuplePayload got %T", payload)
	}
	if len(p.Tuples) == 0 {
		return errors.New("tuple payload must contain at least one tuple")
	}
	return nil
}

func (e *TupleWriteEvent) Execute(ctx context.Context, payload any) error {
	p, ok := payload.(*TuplePayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *TuplePayload got %T", payload)
	}

	tuples := payloadToTuples(p)

	util.Log(ctx).WithField("count", len(tuples)).Debug("writing authorization tuples")

	if writeErr := e.authorizer.WriteTuples(ctx, tuples); writeErr != nil {
		util.Log(ctx).WithError(writeErr).WithFields(map[string]any{
			"tuple_count": len(tuples),
			"tuples":      formatTuples(tuples),
		}).Error("failed to write authorization tuples")
		return writeErr
	}
	return nil
}

// --- TupleDeleteEvent ---

type TupleDeleteEvent struct {
	authorizer security.Authorizer
}

func NewTupleDeleteEventHandler(auth security.Authorizer) events.EventI {
	return &TupleDeleteEvent{authorizer: auth}
}

func (e *TupleDeleteEvent) Name() string {
	return EventKeyAuthzTupleDelete
}

func (e *TupleDeleteEvent) PayloadType() any {
	return &TuplePayload{}
}

func (e *TupleDeleteEvent) Validate(_ context.Context, payload any) error {
	p, ok := payload.(*TuplePayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *TuplePayload got %T", payload)
	}
	if len(p.Tuples) == 0 {
		return errors.New("tuple payload must contain at least one tuple")
	}
	return nil
}

func (e *TupleDeleteEvent) Execute(ctx context.Context, payload any) error {
	p, ok := payload.(*TuplePayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *TuplePayload got %T", payload)
	}

	tuples := payloadToTuples(p)

	util.Log(ctx).WithField("count", len(tuples)).Debug("deleting authorization tuples")

	if delErr := e.authorizer.DeleteTuples(ctx, tuples); delErr != nil {
		util.Log(ctx).WithError(delErr).WithFields(map[string]any{
			"tuple_count": len(tuples),
			"tuples":      formatTuples(tuples),
		}).Error("failed to delete authorization tuples")
		return delErr
	}
	return nil
}
