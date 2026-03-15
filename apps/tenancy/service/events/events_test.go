package events

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
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

// --- typeName ---

func (suite *EventsTestSuite) TestTypeName_Pointer() {
	t := suite.T()
	var m *models.Partition
	assert.Equal(t, "*models.Partition", typeName(m))
}

func (suite *EventsTestSuite) TestTypeName_Value() {
	t := suite.T()
	assert.Equal(t, "string", typeName("hello"))
}

func (suite *EventsTestSuite) TestTypeName_Map() {
	t := suite.T()
	m := map[string]any{}
	assert.Equal(t, "map[string]interface {}", typeName(m))
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
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	assert.Equal(t, EventKeyAuthzPartitionSync, e.Name())
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_PayloadType() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	pt := e.PayloadType()
	_, ok := pt.(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	m := map[string]any{"id": "partition123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_MissingID() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partition id is required")
}

func (suite *EventsTestSuite) TestAuthzPartitionSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- PartitionSyncEvent ---

func (suite *EventsTestSuite) TestPartitionSyncEvent_Name() {
	t := suite.T()
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	assert.Equal(t, EventKeyPartitionSynchronization, e.Name())
}

func (suite *EventsTestSuite) TestPartitionSyncEvent_PayloadType() {
	t := suite.T()
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	pt := e.PayloadType()
	_, ok := pt.(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestPartitionSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	m := map[string]any{"id": "partition123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestPartitionSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- extractStringList ---

func (suite *EventsTestSuite) TestExtractStringList_SpaceSeparated() {
	t := suite.T()
	props := map[string]any{"scope": "openid offline profile"}
	result := extractStringList(props, "scope")
	assert.Equal(t, []string{"openid", "offline", "profile"}, result)
}

func (suite *EventsTestSuite) TestExtractStringList_CommaSeparated() {
	t := suite.T()
	props := map[string]any{"scope": "openid,offline,profile"}
	result := extractStringList(props, "scope")
	assert.Equal(t, []string{"openid", "offline", "profile"}, result)
}

func (suite *EventsTestSuite) TestExtractStringList_Array() {
	t := suite.T()
	props := map[string]any{"audience": []interface{}{"svc1", "svc2", "svc3"}}
	result := extractStringList(props, "audience")
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func (suite *EventsTestSuite) TestExtractStringList_MissingKey() {
	t := suite.T()
	props := map[string]any{}
	result := extractStringList(props, "missing")
	assert.Nil(t, result)
}

func (suite *EventsTestSuite) TestExtractStringList_SingleString() {
	t := suite.T()
	props := map[string]any{"scope": "openid"}
	result := extractStringList(props, "scope")
	// Single string with no separator - returns nil (not split)
	assert.Nil(t, result)
}

func (suite *EventsTestSuite) TestExtractStringList_ArrayWithNonStrings() {
	t := suite.T()
	props := map[string]any{"audience": []interface{}{"svc1", 42, "svc2"}}
	result := extractStringList(props, "audience")
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

// --- prepareRedirectURIs ---

func (suite *EventsTestSuite) TestPrepareRedirectURIs_StringList() {
	t := suite.T()
	partition := &models.Partition{
		Properties: data.JSONMap{"redirect_uris": "https://example.com/callback,https://other.com/cb"},
	}
	uris, err := prepareRedirectURIs(partition)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/callback", "https://other.com/cb"}, uris)
}

func (suite *EventsTestSuite) TestPrepareRedirectURIs_ArrayList() {
	t := suite.T()
	partition := &models.Partition{
		Properties: data.JSONMap{"redirect_uris": []interface{}{
			"https://example.com/callback",
			"https://other.com/cb",
		}},
	}
	uris, err := prepareRedirectURIs(partition)
	require.NoError(t, err)
	assert.Len(t, uris, 2)
}

func (suite *EventsTestSuite) TestPrepareRedirectURIs_NoURIs() {
	t := suite.T()
	partition := &models.Partition{
		Properties: data.JSONMap{},
	}
	uris, err := prepareRedirectURIs(partition)
	require.NoError(t, err)
	assert.Nil(t, uris)
}

func (suite *EventsTestSuite) TestPrepareRedirectURIs_InvalidFormat() {
	t := suite.T()
	partition := &models.Partition{
		Properties: data.JSONMap{"redirect_uris": 12345},
	}
	_, err := prepareRedirectURIs(partition)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid redirect_uris format")
}

// --- preparePayload ---

func (suite *EventsTestSuite) TestPreparePayload_Basic() {
	t := suite.T()
	partition := &models.Partition{
		Name:       "Test Partition",
		Properties: data.JSONMap{},
	}
	partition.ID = "partition-123"

	payload, err := preparePayload("partition-123", partition)
	require.NoError(t, err)

	assert.Equal(t, "Test Partition", payload["client_name"])
	assert.Equal(t, "partition-123", payload["client_id"])
	assert.Equal(t, "none", payload["token_endpoint_auth_method"])
	assert.Contains(t, payload["scope"], "openid")
}

func (suite *EventsTestSuite) TestPreparePayload_WithClientSecret() {
	t := suite.T()
	partition := &models.Partition{
		Name: "Secret Partition",
		Properties: data.JSONMap{
			"client_secret": "my-secret",
		},
	}
	partition.ID = "p-456"

	payload, err := preparePayload("p-456", partition)
	require.NoError(t, err)

	assert.Equal(t, "my-secret", payload["client_secret"])
	assert.Equal(t, "client_secret_post", payload["token_endpoint_auth_method"])
}

func (suite *EventsTestSuite) TestPreparePayload_WithLogoURI() {
	t := suite.T()
	partition := &models.Partition{
		Name:       "Logo Partition",
		Properties: data.JSONMap{"logo_uri": "https://example.com/logo.png"},
	}
	partition.ID = "p-789"

	payload, err := preparePayload("p-789", partition)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/logo.png", payload["logo_uri"])
}

func (suite *EventsTestSuite) TestPreparePayload_WithScopes() {
	t := suite.T()
	partition := &models.Partition{
		Name:       "Scoped",
		Properties: data.JSONMap{"scope": "openid offline custom"},
	}
	partition.ID = "p-s"

	payload, err := preparePayload("p-s", partition)
	require.NoError(t, err)

	assert.Equal(t, "openid offline custom", payload["scope"])
}

func (suite *EventsTestSuite) TestPreparePayload_WithAudience() {
	t := suite.T()
	partition := &models.Partition{
		Name: "Audience",
		Properties: data.JSONMap{
			"audience": []interface{}{"svc1", "svc2"},
		},
	}
	partition.ID = "p-a"

	payload, err := preparePayload("p-a", partition)
	require.NoError(t, err)

	aud, ok := payload["audience"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"svc1", "svc2"}, aud)
}

func (suite *EventsTestSuite) TestPreparePayload_CustomTokenEndpointAuth() {
	t := suite.T()
	partition := &models.Partition{
		Name: "Custom Auth",
		Properties: data.JSONMap{
			"client_secret":              "secret",
			"token_endpoint_auth_method": "private_key_jwt",
		},
	}
	partition.ID = "p-c"

	payload, err := preparePayload("p-c", partition)
	require.NoError(t, err)

	// Custom token_endpoint_auth_method should override default
	assert.Equal(t, "private_key_jwt", payload["token_endpoint_auth_method"])
	// client_secret should NOT be set when custom auth method is used
	_, hasSecret := payload["client_secret"]
	assert.False(t, hasSecret)
}

func (suite *EventsTestSuite) TestPreparePayload_WithRedirectURIs() {
	t := suite.T()
	partition := &models.Partition{
		Name: "Redirect",
		Properties: data.JSONMap{
			"redirect_uris": []interface{}{"https://example.com/cb", "https://other.com/cb"},
		},
	}
	partition.ID = "p-r"

	payload, err := preparePayload("p-r", partition)
	require.NoError(t, err)

	uris, ok := payload["redirect_uris"].([]string)
	require.True(t, ok)
	assert.Len(t, uris, 2)
}

// --- ServiceAccountSyncEvent ---

func (suite *EventsTestSuite) TestServiceAccountSyncEvent_Name() {
	t := suite.T()
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	assert.Equal(t, EventKeyServiceAccountSynchronization, e.Name())
}

func (suite *EventsTestSuite) TestServiceAccountSyncEvent_PayloadType() {
	t := suite.T()
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	_, ok := e.PayloadType().(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestServiceAccountSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	m := map[string]any{"id": "sa-123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestServiceAccountSyncEvent_Validate_MissingID() {
	t := suite.T()
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account id is required")
}

func (suite *EventsTestSuite) TestServiceAccountSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- AuthzServiceAccountSyncEvent ---

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Name() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	assert.Equal(t, EventKeyAuthzServiceAccountSync, e.Name())
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_PayloadType() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	_, ok := e.PayloadType().(*map[string]any)
	assert.True(t, ok)
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_Valid() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	m := map[string]any{"id": "sa-456"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_MissingID() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account id is required")
}

func (suite *EventsTestSuite) TestAuthzServiceAccountSyncEvent_Validate_WrongType() {
	t := suite.T()
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	assert.Error(t, e.Validate(context.Background(), 42))
}

// --- buildServiceAccountHydraPayload ---

func (suite *EventsTestSuite) TestBuildServiceAccountHydraPayload_Internal() {
	t := suite.T()
	sa := &models.ServiceAccount{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		Type:         "internal",
		ProfileID:    "profile-123",
		Audiences:    data.JSONMap{"namespaces": []any{"svc1", "svc2"}},
		BaseModel:    data.BaseModel{TenantID: "tenant-123", PartitionID: "partition-123"},
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Equal(t, "sa-test-client-id", payload["client_name"])
	assert.Equal(t, "test-client-id", payload["client_id"])
	assert.Equal(t, "test-secret", payload["client_secret"])
	assert.Equal(t, "internal openid", payload["scope"])
	assert.Equal(t, []string{"client_credentials"}, payload["grant_types"])
	assert.Equal(t, []string{"token"}, payload["response_types"])
	assert.Equal(t, "profile-123", payload["subject"])
	assert.Equal(t, "client_secret_post", payload["token_endpoint_auth_method"])

	aud, ok := payload["audience"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"svc1", "svc2"}, aud)
	assert.Equal(t, map[string]any{
		"tenant_id":    "tenant-123",
		"partition_id": "partition-123",
		"profile_id":   "profile-123",
		"type":         "internal",
	}, payload["metadata"])
}

func (suite *EventsTestSuite) TestBuildServiceAccountHydraPayload_External() {
	t := suite.T()
	sa := &models.ServiceAccount{
		ClientID:  "ext-client",
		Type:      "external",
		ProfileID: "profile-456",
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Equal(t, "external openid", payload["scope"])
	assert.Equal(t, "none", payload["token_endpoint_auth_method"])
	_, hasSecret := payload["client_secret"]
	assert.False(t, hasSecret)
}

func (suite *EventsTestSuite) TestBuildServiceAccountHydraPayload_NoAudiences() {
	t := suite.T()
	sa := &models.ServiceAccount{
		ClientID:     "no-aud",
		ClientSecret: "secret",
		Type:         "internal",
		ProfileID:    "profile",
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Nil(t, payload["audience"])
}

func (suite *EventsTestSuite) TestBuildServiceAccountHydraPayload_JWKSURIInfersPrivateKeyJWT() {
	t := suite.T()
	sa := &models.ServiceAccount{
		ClientID:     "service-profile",
		ClientSecret: "legacy-secret",
		Type:         "internal",
		ProfileID:    "service_profile",
		Properties: data.JSONMap{
			"jwks_uri": "http://service-profile.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json",
		},
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Equal(t, "private_key_jwt", payload["token_endpoint_auth_method"])
	assert.Equal(
		t,
		"http://service-profile.profile.svc.cluster.local/.well-known/oauth2-client-jwks.json",
		payload["jwks_uri"],
	)
	_, hasSecret := payload["client_secret"]
	assert.False(t, hasSecret)
}

// --- extractAudienceNamespaces ---

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_SliceAny() {
	t := suite.T()
	audiences := data.JSONMap{"namespaces": []any{"svc1", "svc2", "svc3"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_SliceString() {
	t := suite.T()
	audiences := data.JSONMap{"namespaces": []string{"svc1", "svc2"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_CommaSeparated() {
	t := suite.T()
	audiences := data.JSONMap{"namespaces": "svc1,svc2,svc3"}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_SingleString() {
	t := suite.T()
	audiences := data.JSONMap{"namespaces": "svc1"}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1"}, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_Nil() {
	t := suite.T()
	result := extractAudienceNamespaces(nil)
	assert.Nil(t, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_NoNamespacesKey() {
	t := suite.T()
	audiences := data.JSONMap{"other": "value"}
	result := extractAudienceNamespaces(audiences)
	assert.Nil(t, result)
}

func (suite *EventsTestSuite) TestExtractAudienceNamespaces_MixedTypes() {
	t := suite.T()
	audiences := data.JSONMap{"namespaces": []any{"svc1", 42, "svc2"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

// --- Event Key Constants ---

func (suite *EventsTestSuite) TestEventKeyConstants() {
	t := suite.T()
	assert.Equal(t, "authorization.tuple.write", EventKeyAuthzTupleWrite)
	assert.Equal(t, "authorization.tuple.delete", EventKeyAuthzTupleDelete)
	assert.Equal(t, "authorization.partition.sync", EventKeyAuthzPartitionSync)
	assert.Equal(t, "partition.synchronization.event", EventKeyPartitionSynchronization)
	assert.Equal(t, "service_account.synchronization.event", EventKeyServiceAccountSynchronization)
	assert.Equal(t, "authorization.service_account.sync", EventKeyAuthzServiceAccountSync)
}
