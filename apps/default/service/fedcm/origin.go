// Copyright 2023-2026 Ant Investor Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE).

package fedcm

import (
	"fmt"
	"net/url"
	"strings"
)

// OriginMatchesRedirectURIs reports whether the scheme+host+port of origin
// matches the scheme+host+port of any entry in redirectURIs. Malformed entries
// in redirectURIs are skipped rather than returning an error; this avoids a
// single bad registration from breaking validation for the entire client.
func OriginMatchesRedirectURIs(origin string, redirectURIs []string) (bool, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false, fmt.Errorf("origin is empty")
	}
	ou, err := url.Parse(origin)
	if err != nil {
		return false, fmt.Errorf("parse origin: %w", err)
	}
	if ou.Scheme == "" || ou.Host == "" {
		return false, fmt.Errorf("origin missing scheme or host: %q", origin)
	}

	for _, raw := range redirectURIs {
		ru, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || ru.Scheme == "" || ru.Host == "" {
			continue
		}
		if ou.Scheme == ru.Scheme && ou.Host == ru.Host {
			return true, nil
		}
	}
	return false, nil
}
