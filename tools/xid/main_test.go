package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmit_ProducesCountDistinctXids(t *testing.T) {
	var buf bytes.Buffer
	if err := emit(&buf, 5); err != nil {
		t.Fatalf("emit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if len(l) != 20 {
			t.Fatalf("xid %q not 20 chars", l)
		}
		if seen[l] {
			t.Fatalf("duplicate xid %q", l)
		}
		seen[l] = true
	}
}

func TestEmit_ZeroCount(t *testing.T) {
	var buf bytes.Buffer
	if err := emit(&buf, 0); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty output, got %q", buf.String())
	}
}
