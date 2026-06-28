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

package models

import (
	"time"

	"github.com/pitabwire/frame/data"
)

const (
	AuthorizationPolicySchemaVersion = 1

	AuthorizationScopePartitionOnly = "partition_only"
	AuthorizationScopePartitionTree = "partition_tree"

	AuthorizationPolicyPending = "pending"
	AuthorizationPolicyApplied = "applied"
	AuthorizationPolicyFailed  = "failed"
)

// OAuthClientRecipient is the complete set of resource audiences that a
// client may request from the OAuth server. It carries no authorization grant.
type OAuthClientRecipient struct {
	data.BaseModel
	ClientRef        string `gorm:"type:varchar(50);not null;uniqueIndex:idx_oauth_client_recipient,priority:1"`
	ResourceAudience string `gorm:"type:text;not null;uniqueIndex:idx_oauth_client_recipient,priority:2;index"`
}

func (*OAuthClientRecipient) TableName() string { return "oauth_client_recipients" }

// ServiceAccountAuthorizationPolicy tracks desired and applied generations.
// Its child grants and permissions are the authoritative functional-access
// policy; Keto is derived state.
type ServiceAccountAuthorizationPolicy struct {
	data.BaseModel
	ServiceAccountID  string     `gorm:"type:varchar(50);not null;uniqueIndex"`
	SchemaVersion     int32      `gorm:"not null"`
	Generation        int64      `gorm:"not null"`
	AppliedGeneration int64      `gorm:"not null;default:0"`
	Status            string     `gorm:"type:varchar(30);not null;index"`
	RetryCount        int32      `gorm:"not null;default:0"`
	LastErrorCode     string     `gorm:"type:varchar(100)"`
	LastError         string     `gorm:"type:text"`
	NextAttemptAt     *time.Time `gorm:"index"`
	SyncedAt          *time.Time `gorm:"index"`
}

func (*ServiceAccountAuthorizationPolicy) TableName() string {
	return "service_account_authorization_policies"
}

type ServiceAccountAuthorizationGrant struct {
	data.BaseModel
	PolicyID  string `gorm:"type:varchar(50);not null;uniqueIndex:idx_authorization_grant,priority:1;index"`
	Namespace string `gorm:"type:varchar(100);not null;uniqueIndex:idx_authorization_grant,priority:2"`
	Scope     string `gorm:"type:varchar(30);not null;uniqueIndex:idx_authorization_grant,priority:3"`
}

func (*ServiceAccountAuthorizationGrant) TableName() string {
	return "service_account_authorization_grants"
}

type ServiceAccountAuthorizationPermission struct {
	data.BaseModel
	GrantID    string `gorm:"type:varchar(50);not null;uniqueIndex:idx_authorization_permission,priority:1;index"`
	Permission string `gorm:"type:varchar(100);not null;uniqueIndex:idx_authorization_permission,priority:2"`
}

func (*ServiceAccountAuthorizationPermission) TableName() string {
	return "service_account_authorization_permissions"
}

// ServiceAccountAppliedTuple records the exact tuple materialised for a
// policy generation so obsolete relationships can be removed deterministically.
type ServiceAccountAppliedTuple struct {
	data.BaseModel
	PolicyID          string `gorm:"type:varchar(50);not null;index;uniqueIndex:idx_authorization_applied_tuple,priority:1"`
	AppliedGeneration int64  `gorm:"not null;uniqueIndex:idx_authorization_applied_tuple,priority:2"`
	Namespace         string `gorm:"type:varchar(100);not null;uniqueIndex:idx_authorization_applied_tuple,priority:3"`
	Object            string `gorm:"type:varchar(255);not null;uniqueIndex:idx_authorization_applied_tuple,priority:4"`
	Relation          string `gorm:"type:varchar(100);not null;uniqueIndex:idx_authorization_applied_tuple,priority:5"`
	SubjectNamespace  string `gorm:"type:varchar(100);not null;uniqueIndex:idx_authorization_applied_tuple,priority:6"`
	SubjectObject     string `gorm:"type:varchar(255);not null;uniqueIndex:idx_authorization_applied_tuple,priority:7"`
	SubjectRelation   string `gorm:"type:varchar(100);not null;default:'';uniqueIndex:idx_authorization_applied_tuple,priority:8"`
}

func (*ServiceAccountAppliedTuple) TableName() string {
	return "service_account_applied_tuples"
}
