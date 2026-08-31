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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/pitabwire/frame/v2"
)

// httpTestDriver is a frame server driver that binds the address frame hands
// it and serves on an httptest.Server. frametests.WithHTTPTestDriver lets
// httptest pick a random port, which does not work when peers (Hydra login,
// consent and token-hook callbacks) are configured with the service URL
// before the service starts. Binding happens synchronously, so listen and
// startup errors surface directly from svc.Run instead of being lost in a
// goroutine; svc.Stop closes the server.
//
// This mirrors frametests.WithBoundHTTPTestDriver, pending upstream in frame
// (not in v2.1.6); replace WithHTTPTestDriver below with the frame one and
// delete this file once this module depends on a frame release that has it.
type httpTestDriver struct {
	mu  sync.Mutex
	srv *httptest.Server
}

// WithHTTPTestDriver returns a frame option that serves the service on its
// configured port using httptest. Run returns once the listener is bound.
func WithHTTPTestDriver() frame.Option {
	return frame.WithDriver(&httpTestDriver{})
}

func (d *httpTestDriver) ListenAndServe(addr string, h http.Handler) error {
	return d.start(addr, h, false)
}

func (d *httpTestDriver) ListenAndServeTLS(addr, _, _ string, h http.Handler) error {
	return d.start(addr, h, true)
}

func (d *httpTestDriver) start(addr string, h http.Handler, useTLS bool) error {
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := httptest.NewUnstartedServer(h)
	// NewUnstartedServer already opened a loopback listener; swap in ours.
	_ = srv.Listener.Close()
	srv.Listener = listener
	if useTLS {
		srv.StartTLS()
	} else {
		srv.Start()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.srv = srv
	return nil
}

func (d *httpTestDriver) Shutdown(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.srv != nil {
		d.srv.Close()
		d.srv = nil
	}
	return nil
}
