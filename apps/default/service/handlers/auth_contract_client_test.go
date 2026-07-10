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

package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetaString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "t1", metaString(map[string]any{"tenant_id": "t1"}, "tenant_id"))
	require.Equal(t, "", metaString(map[string]any{}, "tenant_id"))
	require.Equal(t, "", metaString(nil, "tenant_id"))
	require.Equal(t, "42", metaString(map[string]any{"partition_id": 42}, "partition_id"))
}

func TestMetadataAsMap(t *testing.T) {
	t.Parallel()

	require.Nil(t, metadataAsMap(nil))
	require.Nil(t, metadataAsMap("not-a-map"))
	m := metadataAsMap(map[string]any{"tenant_id": "t1", "partition_id": "p1"})
	require.Equal(t, "t1", m["tenant_id"])
	require.Equal(t, "p1", m["partition_id"])
}
