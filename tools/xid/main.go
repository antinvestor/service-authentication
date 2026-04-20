// Copyright 2023-2026 Ant Investor Ltd.
// xid generator used by the migration scaffolders.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rs/xid"
)

func emit(w io.Writer, n int) error {
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprintln(w, xid.New().String()); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	count := flag.Int("count", 1, "number of xids to emit")
	flag.Parse()
	if err := emit(os.Stdout, *count); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
