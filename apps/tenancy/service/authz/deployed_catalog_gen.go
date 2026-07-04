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

// Code generated from stawi.org/deployment.manifests/catalog/auth-migration-v2.yaml; DO NOT EDIT.
package authz

import (
	"slices"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/data"
)

var deployedServicePermissions = map[string][]string{ //nolint:gochecknoglobals
	"service_audit": {
		"audit_create",
		"audit_verify",
		"audit_view",
	},
	"service_authentication": {
		"auth_view_all",
		"auth_view_own",
	},
	"service_billing": {
		"billing_run_manage",
		"billing_run_view",
		"catalog_manage",
		"catalog_view",
		"component_manage",
		"credit_manage",
		"credit_view",
		"discount_manage",
		"discount_view",
		"invoice_manage",
		"invoice_view",
		"payment_record",
		"plan_manage",
		"subscription_manage",
		"subscription_view",
		"tier_manage",
		"usage_ingest",
		"usage_view",
	},
	"service_device": {
		"device_key_manage",
		"device_key_view",
		"device_log_manage",
		"device_log_view",
		"device_manage",
		"device_view",
	},
	"service_field": {
		"agent_manage",
		"agent_subagent_manage",
		"agent_view",
		"client_manage",
		"client_relationship_manage",
		"client_relationship_view",
		"client_view",
	},
	"service_file": {
		"content_delete",
		"content_manage",
		"content_upload",
		"content_view",
		"file_access_manage",
		"file_access_view",
	},
	"service_funding": {
		"fund_manage",
		"investor_account_manage",
		"investor_account_view",
	},
	"service_geolocation": {
		"area_manage",
		"area_view",
		"location_ingest",
		"nearby_view",
		"route_manage",
		"route_view",
		"track_view",
	},
	"service_identity": {
		"access_role_assignment_manage",
		"access_role_assignment_view",
		"branch_manage",
		"branch_view",
		"client_data_manage",
		"client_data_verify",
		"client_data_view",
		"client_group_manage",
		"client_group_view",
		"department_manage",
		"department_view",
		"form_submission_manage",
		"form_submission_view",
		"form_template_manage",
		"form_template_view",
		"investor_account_manage",
		"investor_account_view",
		"investor_manage",
		"investor_view",
		"membership_manage",
		"membership_view",
		"organization_manage",
		"organization_view",
		"position_assignment_manage",
		"position_assignment_view",
		"position_manage",
		"position_view",
		"team_manage",
		"team_membership_manage",
		"team_membership_view",
		"team_view",
		"workforce_member_manage",
		"workforce_member_view",
	},
	"service_ledger": {
		"account_manage",
		"account_view",
		"book_manage",
		"book_view",
		"ledger_manage",
		"ledger_view",
		"report_view",
		"transaction_manage",
		"transaction_view",
	},
	"service_limits": {
		"limits_use",
	},
	"service_loans": {
		"client_product_access_manage",
		"client_product_access_view",
		"collection_manage",
		"disbursement_manage",
		"disbursement_view",
		"loan_manage",
		"loan_product_manage",
		"loan_product_view",
		"loan_request_manage",
		"loan_request_submit",
		"loan_request_view",
		"loan_view",
		"penalty_manage",
		"penalty_view",
		"portfolio_export",
		"portfolio_view",
		"reconciliation_manage",
		"repayment_manage",
		"repayment_view",
		"restructure_manage",
		"restructure_view",
	},
	"service_notification": {
		"notification_release",
		"notification_search",
		"notification_send",
		"notification_status_update",
		"notification_status_view",
		"template_manage",
		"template_view",
	},
	"service_operations": {
		"payment_allocate",
		"payment_notify",
		"transfer_execute",
		"transfer_view",
	},
	"service_payment": {
		"payment_link_create",
		"payment_receive",
		"payment_release",
		"payment_search",
		"payment_send",
		"payment_status_update",
		"payment_status_view",
		"prompt_initiate",
		"reconcile",
	},
	"service_profile": {
		"address_manage",
		"contact_manage",
		"profile_create",
		"profile_merge",
		"profile_update",
		"profile_view",
		"relationship_manage",
		"relationship_view",
		"roster_manage",
		"roster_view",
	},
	"service_savings": {
		"deposit_manage",
		"deposit_view",
		"interest_view",
		"savings_account_manage",
		"savings_account_view",
		"savings_balance_view",
		"savings_product_manage",
		"savings_product_view",
		"withdrawal_manage",
		"withdrawal_view",
	},
	"service_setting": {
		"setting_manage",
		"setting_view",
	},
	"service_tenancy": {
		"access_manage",
		"access_view",
		"client_manage",
		"client_view",
		"page_manage",
		"page_view",
		"partition_manage",
		"partition_view",
		"permission_grant",
		"role_manage",
		"service_account_manage",
		"service_account_view",
		"tenant_manage",
		"tenant_view",
	},
	"service_trustage": {
		"event_ingest",
		"execution_resume",
		"execution_retry",
		"execution_view",
		"instance_retry",
		"instance_view",
		"signal_send",
		"workflow_manage",
		"workflow_view",
	},
	"service_checkout": {},
}

var legacyRecipientAudiencePaths = map[string]string{ //nolint:gochecknoglobals
	"opportunities_api":          "/jobs",
	"opportunities_crawler":      "/opportunities-crawler",
	"opportunities_matching":     "/matching",
	"opportunities_materializer": "/opportunities-materializer",
	"opportunities_writer":       "/opportunities-writer",
	"service_audit":              "/audit",
	"service_chat":               "/chat-gateway",
	"service_chat_drone":         "/chat-drone",
	"service_device":             "/devices",
	"service_field":              "/identity",
	"service_file":               "/files",
	"service_files":              "/files",
	"service_funding":            "/funding",
	"service_geolocation":        "/geolocation",
	"service_identity":           "/identity",
	"service_ledger":             "/ledger",
	"service_loans":              "/loans",
	"service_notification":       "/notification",
	"service_operations":         "/operations",
	"service_payment":            "/payment",
	"service_payment_checkout":   "/checkout",
	"service_profile":            "/profile",
	"service_redirect":           "/redirect",
	"service_savings":            "/savings",
	"service_setting":            "/settings",
	"service_tenancy":            "/tenancy",
	"service_thesa":              "/thesa",
	"service_trustage":           "/trustage",
}

func LegacyRecipientAudiencePath(recipient string) (string, bool) {
	path, ok := legacyRecipientAudiencePaths[recipient]
	return path, ok
}

func DeployedPermissions(namespace string) ([]string, bool) {
	permissions, ok := deployedServicePermissions[namespace]
	return slices.Clone(permissions), ok
}
func DeployedServiceNamespaceRecords() []*models.ServiceNamespace {
	namespaces := make([]*models.ServiceNamespace, 0, len(deployedServicePermissions))
	for namespace, permissions := range deployedServicePermissions {
		permissions = slices.Clone(permissions)
		namespaces = append(namespaces, &models.ServiceNamespace{
			Namespace:    namespace,
			Permissions:  data.JSONMap{"values": permissions},
			RoleBindings: data.JSONMap{RoleService: permissions},
		})
	}
	return namespaces
}
