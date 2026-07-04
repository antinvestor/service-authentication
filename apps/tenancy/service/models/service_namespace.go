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

	"github.com/pitabwire/frame/v2/data"
)

// ServiceNamespace stores a registered service's permission namespace,
// available permissions, and role-to-permission mappings. This data is
// published by services at startup and consumed by the authorization
// service to enable dynamic permission management.
type ServiceNamespace struct {
	data.BaseModel
	Namespace    string       `gorm:"type:varchar(100);uniqueIndex;not null"`
	Domain       string       `gorm:"type:varchar(50);not null;default:'platform'"`
	Permissions  data.JSONMap `gorm:"type:jsonb"`
	RoleBindings data.JSONMap `gorm:"type:jsonb"`
	RegisteredAt *time.Time
}

// DomainDefault is the default domain for all namespaces. As the platform
// grows, services can declare their own domain to enable per-domain Keto
// instances — the OPL generator already groups by domain.
const DomainDefault = "platform"
