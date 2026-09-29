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

package tests

import (
	"context"
	"fmt"

	"github.com/pitabwire/frame/v2/frametests"
	"github.com/pitabwire/frame/v2/frametests/definition"
)

// serviceListeningLog is logged by Frame only after the HTTP listener is bound.
// "Initiating server operations" is logged before the bind, so waiting on it
// lets a container that failed to bind look ready.
const serviceListeningLog = "listening on server port"

// assignHostModeHTTPPort gives a host-network service container its own free
// HTTP port. Host-network containers share the host's port space, so a fixed
// port (8083, 8085, ...) collides when several test packages run their
// dependency stacks concurrently: the loser exits with "address already in
// use" and its suite ends up calling another package's container, which
// trusts a different Hydra ("invalid authorization token") or disappears when
// that package tears down ("connection refused").
func assignHostModeHTTPPort(ctx context.Context, d *definition.DefaultImpl) error {
	if !d.Opts().UseHostMode {
		return nil
	}

	port, err := frametests.GetFreePort(ctx)
	if err != nil {
		return fmt.Errorf("allocate host port: %w", err)
	}

	portSpec := fmt.Sprintf("%d/tcp", port)
	d.Opts().Ports[0] = portSpec
	d.DefaultPort = portSpec
	return nil
}
