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
