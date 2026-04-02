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

package utils

import "context"

type contextKey string

func (c contextKey) String() string {
	return "authentication/" + string(c)
}

const ctxKeyDevice = contextKey("deviceKey")
const ctxKeySession = contextKey("sessionKey")

// DeviceIDToContext pushes a device id into the supplied context for easier propagation.
func DeviceIDToContext(ctx context.Context, deviceId string) context.Context {
	return context.WithValue(ctx, ctxKeyDevice, deviceId)
}

// DeviceIDFromContext obtains a device id being propagated through the context.
func DeviceIDFromContext(ctx context.Context) string {
	service, ok := ctx.Value(ctxKeyDevice).(string)
	if !ok {
		return ""
	}

	return service
}

// SessionIDToContext pushes a session id into the supplied context for easier propagation.
func SessionIDToContext(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, ctxKeySession, sessionID)
}

// SessionIDFromContext obtains a session id being propagated through the context.
func SessionIDFromContext(ctx context.Context) string {
	service, ok := ctx.Value(ctxKeySession).(string)
	if !ok {
		return ""
	}

	return service
}
