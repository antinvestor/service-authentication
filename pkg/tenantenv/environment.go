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

package tenantenv

import (
	"fmt"
	"strings"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
)

const (
	Production = "production"
	Staging    = "staging"
)

func Normalise(environment string) string {
	return strings.ToLower(strings.TrimSpace(environment))
}

func IsValid(environment string) bool {
	switch Normalise(environment) {
	case Production, Staging:
		return true
	default:
		return false
	}
}

func FromProto(environment tenancyv1.TenantEnvironment) string {
	switch environment {
	case tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION:
		return Production
	case tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING:
		return Staging
	default:
		return ""
	}
}

func ToProto(environment string) tenancyv1.TenantEnvironment {
	switch Normalise(environment) {
	case Production:
		return tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION
	case Staging:
		return tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING
	default:
		return tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED
	}
}

func ParseToProto(environment string) (tenancyv1.TenantEnvironment, error) {
	value := ToProto(environment)
	if value == tenancyv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED {
		return value, fmt.Errorf("unsupported environment %q: use %s or %s", environment, Production, Staging)
	}

	return value, nil
}
