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

// Package permissionsync registers a service's permission manifest with the
// tenancy service from the migration entrypoint.
//
// Why this exists: Frame's WithPermissionRegistration option only fires the
// manifest POST through a PreStartMethod, which requires svc.Run to be
// invoked. The migration job's main() short-circuits before svc.Run, so the
// manifest is never published. Until the upstream gate is restructured (or
// the migration job is reworked to run the full service lifecycle), this
// helper performs the same POST inline so each service's namespace lands in
// tenancy.service_namespaces and the OPL ConfigMap can be rebuilt.
package permissionsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// EnvVar is the environment variable that points at the tenancy service's
// internal permission-registration endpoint. Mirrors Frame's
// ManifestRegistrationURLEnvVar so the existing chart wiring works.
const EnvVar = "PERMISSIONS_REGISTRATION_URL"

// servicePermissionsExtNumber and the field numbers below mirror the
// constants in Frame's options_permissions.go. They map to the
// ServicePermissions extension on google.protobuf.ServiceOptions defined in
// common/v1/permissions.proto.
const (
	servicePermissionsExtNumber protoreflect.FieldNumber = 50000

	fieldNamespace    protoreflect.FieldNumber = 1
	fieldPermissions  protoreflect.FieldNumber = 2
	fieldRoleBindings protoreflect.FieldNumber = 3
)

// StandardRole enum names from common/v1/permissions.proto. The integer
// values are fixed by the proto definition; do not reorder.
var standardRoleNames = map[int32]string{
	1: "owner",
	2: "admin",
	3: "operator",
	4: "viewer",
	5: "member",
	6: "service",
}

// Register posts the permission manifest for sd to the tenancy registration
// endpoint. Returns nil when EnvVar is unset (the chart unsets it in
// non-migration contexts). Fatal on POST failure — the migration job's exit
// code surfaces this to Kubernetes so the failure is loud rather than silent.
func Register(ctx context.Context, sd protoreflect.ServiceDescriptor) error {
	url := strings.TrimSpace(os.Getenv(EnvVar))
	if url == "" {
		return nil
	}

	manifest := buildManifest(sd)
	if manifest == nil {
		return fmt.Errorf("permissionsync: proto descriptor %s has no service_permissions extension", sd.FullName())
	}

	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("permissionsync: marshal manifest: %w", err)
	}

	postCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("permissionsync: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("permissionsync: POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("permissionsync: registration for %s returned status %d: %s",
			manifest["namespace"], resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	return nil
}

func buildManifest(sd protoreflect.ServiceDescriptor) map[string]any {
	opts := sd.Options()
	if opts == nil {
		return nil
	}

	var manifest map[string]any
	opts.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Number() != servicePermissionsExtNumber || !fd.IsExtension() {
			return true
		}
		manifest = extractFields(v.Message())
		return false
	})
	return manifest
}

func extractFields(extMsg protoreflect.Message) map[string]any {
	desc := extMsg.Descriptor()
	manifest := map[string]any{
		"registered_at": time.Now().UTC(),
	}

	if nsField := desc.Fields().ByNumber(fieldNamespace); nsField != nil {
		ns := extMsg.Get(nsField).String()
		if ns == "" {
			return nil
		}
		manifest["namespace"] = ns
	}

	if permField := desc.Fields().ByNumber(fieldPermissions); permField != nil {
		list := extMsg.Get(permField).List()
		perms := make([]string, list.Len())
		for i := 0; i < list.Len(); i++ {
			perms[i] = list.Get(i).String()
		}
		manifest["permissions"] = perms
	}

	if rbField := desc.Fields().ByNumber(fieldRoleBindings); rbField != nil {
		manifest["role_bindings"] = extractRoleBindings(extMsg.Get(rbField).List())
	}

	return manifest
}

func extractRoleBindings(list protoreflect.List) map[string][]string {
	bindings := make(map[string][]string, list.Len())
	for i := 0; i < list.Len(); i++ {
		rbMsg := list.Get(i).Message()
		roleEnum := rbMsg.Get(rbMsg.Descriptor().Fields().ByNumber(fieldNamespace)).Enum()
		permsList := rbMsg.Get(rbMsg.Descriptor().Fields().ByNumber(fieldPermissions)).List()
		perms := make([]string, permsList.Len())
		for j := 0; j < permsList.Len(); j++ {
			perms[j] = permsList.Get(j).String()
		}
		if name, ok := standardRoleNames[int32(roleEnum)]; ok {
			bindings[name] = perms
		}
	}
	return bindings
}
