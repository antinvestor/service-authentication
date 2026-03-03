package events

import (
	"context"
	"testing"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- typeName ---

func TestTypeName_Pointer(t *testing.T) {
	var m *models.Partition
	assert.Equal(t, "*models.Partition", typeName(m))
}

func TestTypeName_Value(t *testing.T) {
	assert.Equal(t, "string", typeName("hello"))
}

func TestTypeName_Map(t *testing.T) {
	m := map[string]any{}
	assert.Equal(t, "map[string]interface {}", typeName(m))
}

// --- TuplesToPayload / payloadToTuples ---

func TestTuplesToPayload(t *testing.T) {
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

func TestTuplesToPayload_Empty(t *testing.T) {
	payload := TuplesToPayload(nil)
	assert.Empty(t, payload.Tuples)
}

func TestPayloadToTuples_RoundTrip(t *testing.T) {
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

func TestTupleWriteEvent_Name(t *testing.T) {
	e := NewTupleWriteEventHandler(nil)
	assert.Equal(t, EventKeyAuthzTupleWrite, e.Name())
}

func TestTupleWriteEvent_PayloadType(t *testing.T) {
	e := NewTupleWriteEventHandler(nil)
	pt := e.PayloadType()
	_, ok := pt.(*TuplePayload)
	assert.True(t, ok)
}

func TestTupleWriteEvent_Validate_Valid(t *testing.T) {
	e := NewTupleWriteEventHandler(nil)
	payload := &TuplePayload{
		Tuples: []TupleData{
			{ObjectNamespace: "ns", ObjectID: "id", Relation: "rel", SubjectNamespace: "ns2", SubjectID: "sid"},
		},
	}
	assert.NoError(t, e.Validate(context.Background(), payload))
}

func TestTupleWriteEvent_Validate_WrongType(t *testing.T) {
	e := NewTupleWriteEventHandler(nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

func TestTupleWriteEvent_Validate_EmptyTuples(t *testing.T) {
	e := NewTupleWriteEventHandler(nil)
	payload := &TuplePayload{}
	err := e.Validate(context.Background(), payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one tuple")
}

// --- TupleDeleteEvent ---

func TestTupleDeleteEvent_Name(t *testing.T) {
	e := NewTupleDeleteEventHandler(nil)
	assert.Equal(t, EventKeyAuthzTupleDelete, e.Name())
}

func TestTupleDeleteEvent_PayloadType(t *testing.T) {
	e := NewTupleDeleteEventHandler(nil)
	pt := e.PayloadType()
	_, ok := pt.(*TuplePayload)
	assert.True(t, ok)
}

func TestTupleDeleteEvent_Validate_Valid(t *testing.T) {
	e := NewTupleDeleteEventHandler(nil)
	payload := &TuplePayload{
		Tuples: []TupleData{
			{ObjectNamespace: "ns", ObjectID: "id", Relation: "rel", SubjectNamespace: "ns2", SubjectID: "sid"},
		},
	}
	assert.NoError(t, e.Validate(context.Background(), payload))
}

func TestTupleDeleteEvent_Validate_WrongType(t *testing.T) {
	e := NewTupleDeleteEventHandler(nil)
	assert.Error(t, e.Validate(context.Background(), 42))
}

func TestTupleDeleteEvent_Validate_EmptyTuples(t *testing.T) {
	e := NewTupleDeleteEventHandler(nil)
	payload := &TuplePayload{}
	err := e.Validate(context.Background(), payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one tuple")
}

// --- AuthzPartitionSyncEvent ---

func TestAuthzPartitionSyncEvent_Name(t *testing.T) {
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	assert.Equal(t, EventKeyAuthzPartitionSync, e.Name())
}

func TestAuthzPartitionSyncEvent_PayloadType(t *testing.T) {
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	pt := e.PayloadType()
	_, ok := pt.(*map[string]any)
	assert.True(t, ok)
}

func TestAuthzPartitionSyncEvent_Validate_Valid(t *testing.T) {
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	m := map[string]any{"id": "partition123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func TestAuthzPartitionSyncEvent_Validate_MissingID(t *testing.T) {
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partition id is required")
}

func TestAuthzPartitionSyncEvent_Validate_WrongType(t *testing.T) {
	e := NewAuthzPartitionSyncEventHandler(nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- PartitionSyncEvent ---

func TestPartitionSyncEvent_Name(t *testing.T) {
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	assert.Equal(t, EventKeyPartitionSynchronization, e.Name())
}

func TestPartitionSyncEvent_PayloadType(t *testing.T) {
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	pt := e.PayloadType()
	_, ok := pt.(*map[string]any)
	assert.True(t, ok)
}

func TestPartitionSyncEvent_Validate_Valid(t *testing.T) {
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	m := map[string]any{"id": "partition123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func TestPartitionSyncEvent_Validate_WrongType(t *testing.T) {
	e := NewPartitionSynchronizationEventHandler(context.Background(), nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- extractStringList ---

func TestExtractStringList_SpaceSeparated(t *testing.T) {
	props := map[string]any{"scope": "openid offline profile"}
	result := extractStringList(props, "scope")
	assert.Equal(t, []string{"openid", "offline", "profile"}, result)
}

func TestExtractStringList_CommaSeparated(t *testing.T) {
	props := map[string]any{"scope": "openid,offline,profile"}
	result := extractStringList(props, "scope")
	assert.Equal(t, []string{"openid", "offline", "profile"}, result)
}

func TestExtractStringList_Array(t *testing.T) {
	props := map[string]any{"audience": []interface{}{"svc1", "svc2", "svc3"}}
	result := extractStringList(props, "audience")
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func TestExtractStringList_MissingKey(t *testing.T) {
	props := map[string]any{}
	result := extractStringList(props, "missing")
	assert.Nil(t, result)
}

func TestExtractStringList_SingleString(t *testing.T) {
	props := map[string]any{"scope": "openid"}
	result := extractStringList(props, "scope")
	// Single string with no separator - returns nil (not split)
	assert.Nil(t, result)
}

func TestExtractStringList_ArrayWithNonStrings(t *testing.T) {
	props := map[string]any{"audience": []interface{}{"svc1", 42, "svc2"}}
	result := extractStringList(props, "audience")
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

// --- prepareRedirectURIs ---

func TestPrepareRedirectURIs_StringList(t *testing.T) {
	partition := &models.Partition{
		Properties: data.JSONMap{"redirect_uris": "https://example.com/callback,https://other.com/cb"},
	}
	uris, err := prepareRedirectURIs(partition)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://example.com/callback", "https://other.com/cb"}, uris)
}

func TestPrepareRedirectURIs_ArrayList(t *testing.T) {
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

func TestPrepareRedirectURIs_NoURIs(t *testing.T) {
	partition := &models.Partition{
		Properties: data.JSONMap{},
	}
	uris, err := prepareRedirectURIs(partition)
	require.NoError(t, err)
	assert.Nil(t, uris)
}

func TestPrepareRedirectURIs_InvalidFormat(t *testing.T) {
	partition := &models.Partition{
		Properties: data.JSONMap{"redirect_uris": 12345},
	}
	_, err := prepareRedirectURIs(partition)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid redirect_uris format")
}

// --- preparePayload ---

func TestPreparePayload_Basic(t *testing.T) {
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

func TestPreparePayload_WithClientSecret(t *testing.T) {
	partition := &models.Partition{
		Name:         "Secret Partition",
		ClientSecret: "my-secret",
		Properties:   data.JSONMap{},
	}
	partition.ID = "p-456"

	payload, err := preparePayload("p-456", partition)
	require.NoError(t, err)

	assert.Equal(t, "my-secret", payload["client_secret"])
	assert.Equal(t, "client_secret_post", payload["token_endpoint_auth_method"])
}

func TestPreparePayload_WithLogoURI(t *testing.T) {
	partition := &models.Partition{
		Name:       "Logo Partition",
		Properties: data.JSONMap{"logo_uri": "https://example.com/logo.png"},
	}
	partition.ID = "p-789"

	payload, err := preparePayload("p-789", partition)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/logo.png", payload["logo_uri"])
}

func TestPreparePayload_WithScopes(t *testing.T) {
	partition := &models.Partition{
		Name:       "Scoped",
		Properties: data.JSONMap{"scope": "openid offline custom"},
	}
	partition.ID = "p-s"

	payload, err := preparePayload("p-s", partition)
	require.NoError(t, err)

	assert.Equal(t, "openid offline custom", payload["scope"])
}

func TestPreparePayload_WithAudience(t *testing.T) {
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

func TestPreparePayload_CustomTokenEndpointAuth(t *testing.T) {
	partition := &models.Partition{
		Name:         "Custom Auth",
		ClientSecret: "secret",
		Properties:   data.JSONMap{"token_endpoint_auth_method": "private_key_jwt"},
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

func TestPreparePayload_WithRedirectURIs(t *testing.T) {
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

func TestServiceAccountSyncEvent_Name(t *testing.T) {
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	assert.Equal(t, EventKeyServiceAccountSynchronization, e.Name())
}

func TestServiceAccountSyncEvent_PayloadType(t *testing.T) {
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	_, ok := e.PayloadType().(*map[string]any)
	assert.True(t, ok)
}

func TestServiceAccountSyncEvent_Validate_Valid(t *testing.T) {
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	m := map[string]any{"id": "sa-123"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func TestServiceAccountSyncEvent_Validate_MissingID(t *testing.T) {
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account id is required")
}

func TestServiceAccountSyncEvent_Validate_WrongType(t *testing.T) {
	e := NewServiceAccountSynchronizationEventHandler(context.Background(), nil, nil, nil, nil)
	assert.Error(t, e.Validate(context.Background(), "invalid"))
}

// --- AuthzServiceAccountSyncEvent ---

func TestAuthzServiceAccountSyncEvent_Name(t *testing.T) {
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	assert.Equal(t, EventKeyAuthzServiceAccountSync, e.Name())
}

func TestAuthzServiceAccountSyncEvent_PayloadType(t *testing.T) {
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	_, ok := e.PayloadType().(*map[string]any)
	assert.True(t, ok)
}

func TestAuthzServiceAccountSyncEvent_Validate_Valid(t *testing.T) {
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	m := map[string]any{"id": "sa-456"}
	assert.NoError(t, e.Validate(context.Background(), &m))
}

func TestAuthzServiceAccountSyncEvent_Validate_MissingID(t *testing.T) {
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	m := map[string]any{"other": "value"}
	err := e.Validate(context.Background(), &m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service account id is required")
}

func TestAuthzServiceAccountSyncEvent_Validate_WrongType(t *testing.T) {
	e := NewAuthzServiceAccountSyncEventHandler(nil, nil)
	assert.Error(t, e.Validate(context.Background(), 42))
}

// --- buildServiceAccountHydraPayload ---

func TestBuildServiceAccountHydraPayload_Internal(t *testing.T) {
	sa := &models.ServiceAccount{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		Type:         "internal",
		ProfileID:    "profile-123",
		Audiences:    data.JSONMap{"namespaces": []any{"svc1", "svc2"}},
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Equal(t, "sa-test-client-id", payload["client_name"])
	assert.Equal(t, "test-client-id", payload["client_id"])
	assert.Equal(t, "test-secret", payload["client_secret"])
	assert.Equal(t, "system_int openid", payload["scope"])
	assert.Equal(t, []string{"client_credentials"}, payload["grant_types"])
	assert.Equal(t, []string{"token"}, payload["response_types"])
	assert.Equal(t, "profile-123", payload["subject"])
	assert.Equal(t, "client_secret_post", payload["token_endpoint_auth_method"])

	aud, ok := payload["audience"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"svc1", "svc2"}, aud)
}

func TestBuildServiceAccountHydraPayload_External(t *testing.T) {
	sa := &models.ServiceAccount{
		ClientID:  "ext-client",
		Type:      "external",
		ProfileID: "profile-456",
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Equal(t, "system_ext openid", payload["scope"])
	assert.Equal(t, "none", payload["token_endpoint_auth_method"])
	_, hasSecret := payload["client_secret"]
	assert.False(t, hasSecret)
}

func TestBuildServiceAccountHydraPayload_NoAudiences(t *testing.T) {
	sa := &models.ServiceAccount{
		ClientID:     "no-aud",
		ClientSecret: "secret",
		Type:         "internal",
		ProfileID:    "profile",
	}

	payload := buildServiceAccountHydraPayload(sa)

	assert.Nil(t, payload["audience"])
}

// --- extractAudienceNamespaces ---

func TestExtractAudienceNamespaces_SliceAny(t *testing.T) {
	audiences := data.JSONMap{"namespaces": []any{"svc1", "svc2", "svc3"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func TestExtractAudienceNamespaces_SliceString(t *testing.T) {
	audiences := data.JSONMap{"namespaces": []string{"svc1", "svc2"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

func TestExtractAudienceNamespaces_CommaSeparated(t *testing.T) {
	audiences := data.JSONMap{"namespaces": "svc1,svc2,svc3"}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2", "svc3"}, result)
}

func TestExtractAudienceNamespaces_SingleString(t *testing.T) {
	audiences := data.JSONMap{"namespaces": "svc1"}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1"}, result)
}

func TestExtractAudienceNamespaces_Nil(t *testing.T) {
	result := extractAudienceNamespaces(nil)
	assert.Nil(t, result)
}

func TestExtractAudienceNamespaces_NoNamespacesKey(t *testing.T) {
	audiences := data.JSONMap{"other": "value"}
	result := extractAudienceNamespaces(audiences)
	assert.Nil(t, result)
}

func TestExtractAudienceNamespaces_MixedTypes(t *testing.T) {
	audiences := data.JSONMap{"namespaces": []any{"svc1", 42, "svc2"}}
	result := extractAudienceNamespaces(audiences)
	assert.Equal(t, []string{"svc1", "svc2"}, result)
}

// --- Event Key Constants ---

func TestEventKeyConstants(t *testing.T) {
	assert.Equal(t, "authorization.tuple.write", EventKeyAuthzTupleWrite)
	assert.Equal(t, "authorization.tuple.delete", EventKeyAuthzTupleDelete)
	assert.Equal(t, "authorization.partition.sync", EventKeyAuthzPartitionSync)
	assert.Equal(t, "partition.synchronization.event", EventKeyPartitionSynchronization)
	assert.Equal(t, "service_account.synchronization.event", EventKeyServiceAccountSynchronization)
	assert.Equal(t, "authorization.service_account.sync", EventKeyAuthzServiceAccountSync)
}
