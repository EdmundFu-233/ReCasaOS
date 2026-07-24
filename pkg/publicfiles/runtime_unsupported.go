//go:build !linux

package publicfiles

import (
	"errors"
	"fmt"
)

var ErrUnsafeServiceRuntime = errors.New("public file service runtime isolation is unsafe")

func ValidateServiceRuntime() error {
	return fmt.Errorf("%w: Linux is required", ErrUnsafeServiceRuntime)
}
