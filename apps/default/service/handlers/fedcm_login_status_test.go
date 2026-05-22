// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests lock in the exact header name + values the FedCM Login Status
// API expects. Chrome ignores a malformed Set-Login header silently, so a
// rename or typo would degrade analytics-free without surfacing any error —
// asserting the values here makes a regression fail loudly in CI instead.

func TestSetLoginStatusLoggedIn_HeaderShape(t *testing.T) {
	rec := httptest.NewRecorder()
	setLoginStatusLoggedIn(rec)
	require.Equal(t, "logged-in", rec.Header().Get("Set-Login"))
}

func TestSetLoginStatusLoggedOut_HeaderShape(t *testing.T) {
	rec := httptest.NewRecorder()
	setLoginStatusLoggedOut(rec)
	require.Equal(t, "logged-out", rec.Header().Get("Set-Login"))
}

// TestSetLoginStatus_Overwrites verifies that calling the logout helper
// after the login helper produces the most-recent header value — Chrome
// only honours the final Set-Login on the response.
func TestSetLoginStatus_Overwrites(t *testing.T) {
	rec := httptest.NewRecorder()
	setLoginStatusLoggedIn(rec)
	setLoginStatusLoggedOut(rec)
	require.Equal(t, "logged-out", rec.Header().Get("Set-Login"))
}
