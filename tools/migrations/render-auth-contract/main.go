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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/authz"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/config"
	"github.com/pitabwire/util"
)

type grantInput struct {
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	clientID := flag.String("client-id", "", "OAuth client database ID")
	tenantID := flag.String("tenant-id", "", "tenant ID")
	partitionID := flag.String("partition-id", "", "partition ID")
	recipientsJSON := flag.String("recipients", "[]", "JSON array of canonical resource audience URLs")
	serviceAccountID := flag.String("service-account-id", "", "service account database ID")
	policyID := flag.String("policy-id", "", "authorization policy database ID")
	grantsJSON := flag.String("grants", "{}", "JSON object of explicit authorization grants")
	flag.Parse()

	if strings.TrimSpace(*clientID) == "" || strings.TrimSpace(*tenantID) == "" || strings.TrimSpace(*partitionID) == "" {
		return errors.New("client-id, tenant-id, and partition-id are required")
	}

	var recipients []string
	if err := json.Unmarshal([]byte(*recipientsJSON), &recipients); err != nil {
		return fmt.Errorf("parse recipients: %w", err)
	}
	slices.Sort(recipients)
	recipients = slices.Compact(recipients)
	if len(recipients) == 0 {
		return errors.New("at least one recipient is required")
	}
	for _, recipient := range recipients {
		if _, err := config.ParseResourceAudience(recipient); err != nil {
			return fmt.Errorf("invalid recipient %q: %w", recipient, err)
		}
		fmt.Printf(
			"\nINSERT INTO oauth_client_recipients (id, tenant_id, partition_id, client_ref, resource_audience) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING;\n",
			quote(util.IDString()), quote(*tenantID), quote(*partitionID), quote(*clientID), quote(recipient),
		)
	}

	if strings.TrimSpace(*serviceAccountID) == "" {
		return nil
	}
	if strings.TrimSpace(*policyID) == "" {
		return errors.New("policy-id is required with service-account-id")
	}

	var grants map[string]grantInput
	if err := json.Unmarshal([]byte(*grantsJSON), &grants); err != nil {
		return fmt.Errorf("parse grants: %w", err)
	}
	if len(grants) == 0 {
		return errors.New("at least one authorization grant is required with service-account-id")
	}
	requested := make(map[string][]string, len(grants))
	for namespace, grant := range grants {
		if grant.Scope != models.AuthorizationScopePartitionOnly && grant.Scope != models.AuthorizationScopePartitionTree {
			return fmt.Errorf("grant %q has invalid scope %q", namespace, grant.Scope)
		}
		requested[namespace] = grant.Permissions
	}
	resolved, err := authz.ResolveServiceGrants(requested, authz.DeployedServiceNamespaceRecords())
	if err != nil {
		return fmt.Errorf("validate grants: %w", err)
	}

	fmt.Printf(
		"\nINSERT INTO service_account_authorization_policies (id, tenant_id, partition_id, service_account_id, schema_version, generation, applied_generation, status, retry_count) VALUES (%s, %s, %s, %s, %d, 1, 0, %s, 0) ON CONFLICT (id) DO NOTHING;\n",
		quote(*policyID), quote(*tenantID), quote(*partitionID), quote(*serviceAccountID),
		models.AuthorizationPolicySchemaVersion, quote(models.AuthorizationPolicyPending),
	)

	namespaces := make([]string, 0, len(resolved))
	for namespace := range resolved {
		namespaces = append(namespaces, namespace)
	}
	slices.Sort(namespaces)
	for _, namespace := range namespaces {
		grantID := util.IDString()
		fmt.Printf(
			"\nINSERT INTO service_account_authorization_grants (id, tenant_id, partition_id, policy_id, namespace, scope) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING;\n",
			quote(grantID), quote(*tenantID), quote(*partitionID), quote(*policyID), quote(namespace), quote(grants[namespace].Scope),
		)
		for _, permission := range resolved[namespace] {
			fmt.Printf(
				"INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING;\n",
				quote(util.IDString()), quote(*tenantID), quote(*partitionID), quote(grantID), quote(permission),
			)
		}
	}
	return nil
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
