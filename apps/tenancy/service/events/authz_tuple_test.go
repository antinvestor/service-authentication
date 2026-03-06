package events

import (
	"context"
	"testing"

	"github.com/pitabwire/frame/security"
	"github.com/stretchr/testify/suite"
)

type AuthzTupleTestSuite struct {
	suite.Suite
}

// --- TuplesToPayload ---

func (s *AuthzTupleTestSuite) TestTuplesToPayload() {
	tuples := []security.RelationTuple{
		{
			Object:   security.ObjectRef{Namespace: "ns1", ID: "obj1"},
			Relation: "rel1",
			Subject:  security.SubjectRef{Namespace: "ns2", ID: "sub1", Relation: "member"},
		},
		{
			Object:   security.ObjectRef{Namespace: "ns3", ID: "obj2"},
			Relation: "rel2",
			Subject:  security.SubjectRef{Namespace: "ns4", ID: "sub2"},
		},
	}

	payload := TuplesToPayload(tuples)
	s.Len(payload.Tuples, 2)
	s.Equal("ns1", payload.Tuples[0].ObjectNamespace)
	s.Equal("obj1", payload.Tuples[0].ObjectID)
	s.Equal("rel1", payload.Tuples[0].Relation)
	s.Equal("ns2", payload.Tuples[0].SubjectNamespace)
	s.Equal("sub1", payload.Tuples[0].SubjectID)
	s.Equal("member", payload.Tuples[0].SubjectRelation)

	s.Equal("ns3", payload.Tuples[1].ObjectNamespace)
	s.Equal("", payload.Tuples[1].SubjectRelation)
}

func (s *AuthzTupleTestSuite) TestTuplesToPayload_Empty() {
	payload := TuplesToPayload(nil)
	s.Empty(payload.Tuples)
}

// --- payloadToTuples ---

func (s *AuthzTupleTestSuite) TestPayloadToTuples() {
	p := &TuplePayload{
		Tuples: []TupleData{
			{
				ObjectNamespace:  "ns1",
				ObjectID:         "obj1",
				Relation:         "rel1",
				SubjectNamespace: "ns2",
				SubjectID:        "sub1",
				SubjectRelation:  "member",
			},
		},
	}

	tuples := payloadToTuples(p)
	s.Len(tuples, 1)
	s.Equal("ns1", tuples[0].Object.Namespace)
	s.Equal("obj1", tuples[0].Object.ID)
	s.Equal("rel1", tuples[0].Relation)
	s.Equal("ns2", tuples[0].Subject.Namespace)
	s.Equal("sub1", tuples[0].Subject.ID)
	s.Equal("member", tuples[0].Subject.Relation)
}

// --- TupleWriteEvent ---

func (s *AuthzTupleTestSuite) TestTupleWriteEvent_Name() {
	e := NewTupleWriteEventHandler(nil)
	s.Equal(EventKeyAuthzTupleWrite, e.Name())
}

func (s *AuthzTupleTestSuite) TestTupleWriteEvent_PayloadType() {
	e := NewTupleWriteEventHandler(nil)
	s.IsType(&TuplePayload{}, e.PayloadType())
}

func (s *AuthzTupleTestSuite) TestTupleWriteEvent_Validate_Valid() {
	e := NewTupleWriteEventHandler(nil)
	p := &TuplePayload{Tuples: []TupleData{{ObjectNamespace: "ns"}}}
	s.NoError(e.Validate(context.Background(), p))
}

func (s *AuthzTupleTestSuite) TestTupleWriteEvent_Validate_Empty() {
	e := NewTupleWriteEventHandler(nil)
	s.Error(e.Validate(context.Background(), &TuplePayload{}))
}

func (s *AuthzTupleTestSuite) TestTupleWriteEvent_Validate_WrongType() {
	e := NewTupleWriteEventHandler(nil)
	s.Error(e.Validate(context.Background(), "wrong"))
}

// --- TupleDeleteEvent ---

func (s *AuthzTupleTestSuite) TestTupleDeleteEvent_Name() {
	e := NewTupleDeleteEventHandler(nil)
	s.Equal(EventKeyAuthzTupleDelete, e.Name())
}

func (s *AuthzTupleTestSuite) TestTupleDeleteEvent_PayloadType() {
	e := NewTupleDeleteEventHandler(nil)
	s.IsType(&TuplePayload{}, e.PayloadType())
}

func (s *AuthzTupleTestSuite) TestTupleDeleteEvent_Validate_Valid() {
	e := NewTupleDeleteEventHandler(nil)
	p := &TuplePayload{Tuples: []TupleData{{ObjectNamespace: "ns"}}}
	s.NoError(e.Validate(context.Background(), p))
}

func (s *AuthzTupleTestSuite) TestTupleDeleteEvent_Validate_Empty() {
	e := NewTupleDeleteEventHandler(nil)
	s.Error(e.Validate(context.Background(), &TuplePayload{}))
}

func (s *AuthzTupleTestSuite) TestTupleDeleteEvent_Validate_WrongType() {
	e := NewTupleDeleteEventHandler(nil)
	s.Error(e.Validate(context.Background(), 42))
}

// --- Roundtrip ---

func (s *AuthzTupleTestSuite) TestRoundtrip_TuplesToPayloadToTuples() {
	original := []security.RelationTuple{
		{
			Object:   security.ObjectRef{Namespace: "tenancy_access", ID: "t1/p1"},
			Relation: "member",
			Subject:  security.SubjectRef{Namespace: "profile_user", ID: "prof-1"},
		},
		{
			Object:   security.ObjectRef{Namespace: "tenancy_access", ID: "t1/child"},
			Relation: "member",
			Subject:  security.SubjectRef{Namespace: "tenancy_access", ID: "t1/parent", Relation: "member"},
		},
	}

	payload := TuplesToPayload(original)
	result := payloadToTuples(payload)

	s.Len(result, 2)
	for i, t := range result {
		s.Equal(original[i].Object.Namespace, t.Object.Namespace)
		s.Equal(original[i].Object.ID, t.Object.ID)
		s.Equal(original[i].Relation, t.Relation)
		s.Equal(original[i].Subject.Namespace, t.Subject.Namespace)
		s.Equal(original[i].Subject.ID, t.Subject.ID)
		s.Equal(original[i].Subject.Relation, t.Subject.Relation)
	}
}

func TestAuthzTuple(t *testing.T) {
	suite.Run(t, new(AuthzTupleTestSuite))
}
