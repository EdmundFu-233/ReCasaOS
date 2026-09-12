//go:build !linux || android

package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(
		os.Stderr,
		"ReCasaOS runtime requires Linux; refusing to start on %s.\n",
		runtime.GOOS,
	)
	os.Exit(1)
}
