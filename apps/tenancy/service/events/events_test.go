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
	"testing"

	"github.com/pitabwire/frame/v2/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type EventsTestSuite struct {
	suite.Suite
}

func TestEventsTestSuite(t *testing.T) {
	suite.Run(t, new(EventsTestSuite))
}

// --- TuplesToPayload / payloadToTuples ---

func (suite *EventsTestSuite) TestTuplesToPayload() {
	t := suite.T()
	tuples := []security.RelationTuple{
		{
			Object:   security.ObjectRef{Namespace: "ns1", ID: "obj1"},
			Relation: "member",
			Subject:  security.SubjectRef{Namespace: "ns2", ID: "sub1"},
		},
		{
			Object:   security.ObjectRef{Namespace: "ns3", ID: "obj2"},
			Relation: "owner",
			Subject:  security.SubjectRef{Namespace: "ns4", ID: "sub2", Relation: "member"},
		},
	}

	payload := TuplesToPayload(tuples)
	require.Len(t, payload.Tuples, 2)

	assert.Equal(t, "ns1", payload.Tuples[0].ObjectNamespace)
	assert.Equal(t, "obj1", payload.Tuples[0].ObjectID)
	assert.Equal(t, "member", payload.Tuples[0].Relation)
	assert.Equal(t, "ns2", payload.Tuples[0].SubjectNamespace)
	assert.Equal(t, "sub1", payload.Tuples[0].SubjectID)
	assert.Equal(t, "", payload.Tuples[0].SubjectRelation)

	assert.Equal(t, "member", payload.Tuples[1].SubjectRelation)
}

func (suite *EventsTestSuite) TestTuplesToPayload_Empty() {
	t := suite.T()
	payload := TuplesToPayload(nil)
	assert.Empty(t, payload.Tuples)
}

func (suite *EventsTestSuite) TestPayloadToTuples_RoundTrip() {
	t := suite.T()
	original := []security.RelationTuple{
		{
			Object:   security.ObjectRef{Namespace: "service_tenancy", ID: "t1/p1"},
			Relation: "owner",
			Subject:  security.SubjectRef{Namespace: "profile_user", ID: "user1"},
		},
		{
			Object:   security.ObjectRef{Namespace: "tenancy_access", ID: "t1/p1"},
			Relation: "member",
			Subject:  security.SubjectRef{Namespace: "tenancy_access", ID: "t1/p0", Relation: "member"},
		},
	}

	payload := TuplesToPayload(original)
	result := payloadToTuples(payload)

	require.Len(t, result, 2)
	assert.Equal(t, original[0].Object.Namespace, result[0].Object.Namespace)
	assert.Equal(t, original[0].Object.ID, result[0].Object.ID)
	assert.Equal(t, original[0].Relation, result[0].Relation)
	assert.Equal(t, original[0].Subject.ID, result[0].Subject.ID)
	assert.Equal(t, original[1].Subject.Relation, result[1].Subject.Relation)
}

// --- TupleWriteEvent ---

func (suite *EventsTestSuite) TestTupleWriteEvent_Name() {
	t := suite.T()
	e := NewTupleWriteEventHandler(nil)
	assert.Equal(t, EventKeyAuthzTupleWrite, e.Name())
}

func (suite *EventsTestSuite) TestTupleWriteEvent_PayloadType() {
	t := suite.T()
	e := NewTupleWriteEventHandler(nil)
	pt := e.PayloadType()
	_, ok := pt.(*TuplePayload)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestTupleWriteEvent_Validate_Valid() {
	t := suite.T()
	e := NewTupleWriteEventHandler(nil)
	payload := &TuplePayload{
		Tuples: []TupleData{
			{ObjectNamespace: "ns", ObjectID: "id", Relation: "rel", SubjectNamespace: "ns2", SubjectID: "sid"},
		},
	}
	assert.NoError(t, e.Validate(context.Background(), payload))
}

func (suite *EventsTestSuite) TestTupleWriteEvent_Validate_WrongType() {
	t := suite.T()
	e := NewTupleWriteEventHandler(nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

func (suite *EventsTestSuite) TestTupleWriteEvent_Validate_EmptyTuples() {
	t := suite.T()
	e := NewTupleWriteEventHandler(nil)
	payload := &TuplePayload{}
	err := e.Validate(context.Background(), payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one tuple")
}

// --- TupleDeleteEvent ---

func (suite *EventsTestSuite) TestTupleDeleteEvent_Name() {
	t := suite.T()
	e := NewTupleDeleteEventHandler(nil)
	assert.Equal(t, EventKeyAuthzTupleDelete, e.Name())
}

func (suite *EventsTestSuite) TestTupleDeleteEvent_PayloadType() {
	t := suite.T()
	e := NewTupleDeleteEventHandler(nil)
	pt := e.PayloadType()
	_, ok := pt.(*TuplePayload)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestTupleDeleteEvent_Validate_Valid() {
	t := suite.T()
	e := NewTupleDeleteEventHandler(nil)
	payload := &TuplePayload{
		Tuples: []TupleData{
			{ObjectNamespace: "ns", ObjectID: "id", Relation: "rel", SubjectNamespace: "ns2", SubjectID: "sid"},
		},
	}
	assert.NoError(t, e.Validate(context.Background(), payload))
}

func (suite *EventsTestSuite) TestTupleDeleteEvent_Validate_WrongType() {
	t := suite.T()
	e := NewTupleDeleteEventHandler(nil)
	assert.Error(t, e.Validate(context.Background(), 42))
}

func (suite *EventsTestSuite) TestTupleDeleteEvent_Validate_EmptyTuples() {
	t := suite.T()
	e := NewTupleDeleteEventHandler(nil)
	payload := &TuplePayload{}
	err := e.Validate(context.Background(), payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one tuple")
}

// --- AuthzPartitionSyncEvent ---

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Name() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil, nil, nil, nil, nil)
	assert.Equal(t, EventKeyAuthzPartitionSync, e.Name())
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_PayloadType() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil, nil, nil, nil, nil)
	pt := e.PayloadType()
	_, ok := pt.(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil, nil, nil, nil, nil)
	m := map[string]any{"id": "partition123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_MissingID() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil, nil, nil, nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partition id is required")
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil, nil, nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- AuthzServiceAccountSyncEvent ---

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Name() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	assert.Equal(t, EventKeyAuthzServiceAccountSync, e.Name())
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_PayloadType() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	_, ok := e.PayloadType().(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	m := map[string]any{"id": "sa-456", "generation": float64(1)}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_GenerationRepresentations() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)

	for name, generation := range map[string]any{
		"queue JSON":     float64(2),
		"startup direct": int64(2),
		"native integer": 2,
	} {
		t.Run(name, func(t *testing.T) {
			payload := map[string]any{"id": "sa-456", "generation": generation}
			assert.NoError(t, e.Validate(context.Background(), &payload))
		})
	}

	for name, generation := range map[string]any{
		"fractional": float64(1.5),
		"string":     "2",
	} {
		t.Run(name, func(t *testing.T) {
			payload := map[string]any{"id": "sa-456", "generation": generation}
			assert.Error(t, e.Validate(context.Background(), &payload))
		})
	}
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_MissingID() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account id is required")
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil, nil, nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), 42))
}

// --- Event Key Constants ---

func (suite *EventsTestSuite) TestEventKeyConstants() {
	t := suite.T()
	assert.Equal(t, "authorization.tuple.write", EventKeyAuthzTupleWrite)
	assert.Equal(t, "authorization.tuple.delete", EventKeyAuthzTupleDelete)
	assert.Equal(t, "authorization.partition.sync", EventKeyAuthzPartitionSync)
	assert.Equal(t, "authorization.service_account.sync", EventKeyAuthzServiceAccountSync)
}
