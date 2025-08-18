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