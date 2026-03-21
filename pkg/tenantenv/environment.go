package tenantenv

import (
	"fmt"
	"strings"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
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

func FromProto(environment partitionv1.TenantEnvironment) string {
	switch environment {
	case partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION:
		return Production
	case partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING:
		return Staging
	default:
		return ""
	}
}

func ToProto(environment string) partitionv1.TenantEnvironment {
	switch Normalise(environment) {
	case Production:
		return partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_PRODUCTION
	case Staging:
		return partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_STAGING
	default:
		return partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED
	}
}

func ParseToProto(environment string) (partitionv1.TenantEnvironment, error) {
	value := ToProto(environment)
	if value == partitionv1.TenantEnvironment_TENANT_ENVIRONMENT_UNSPECIFIED {
		return value, fmt.Errorf("unsupported environment %q: use %s or %s", environment, Production, Staging)
	}

	return value, nil
}
