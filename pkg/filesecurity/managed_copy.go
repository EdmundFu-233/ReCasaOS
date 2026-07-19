package filesecurity

import (
	"errors"
	"fmt"
)

// ManagedConflictStyle controls how a descriptor-relative copy or move deals
// with an existing destination. Callers must opt in to one of the explicit
// policies; an empty or unknown value fails closed.
type ManagedConflictStyle string

const (
	ManagedConflictSkip    ManagedConflictStyle = "skip"
	ManagedConflictReplace ManagedConflictStyle = "replace"
	ManagedConflictRename  ManagedConflictStyle = "rename"
)

var ErrInvalidManagedConflictStyle = errors.New("invalid managed copy conflict style")

var (
	ErrUnsafeManagedDirectoryTransfer           = errors.New("unsafe managed directory transfer")
	ErrManagedDirectoryMoveRequiresAtomicRename = errors.New("managed directory move requires a same-filesystem atomic rename")
	ErrManagedMoveSourceRetained                = errors.New("managed copy-first move published the destination but retained the source")
)

// ParseManagedConflictStyle accepts only the policies implemented by
// ManagedRoots. "overwrite" is the one legacy CasaOS-UI spelling and is
// normalized to replace. Every other unknown value fails closed instead of
// silently selecting destructive replacement.
func ParseManagedConflictStyle(value string) (ManagedConflictStyle, error) {
	if value == "overwrite" {
		return ManagedConflictReplace, nil
	}
	style := ManagedConflictStyle(value)
	switch style {
	case ManagedConflictSkip, ManagedConflictReplace, ManagedConflictRename:
		return style, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidManagedConflictStyle, value)
	}
}

// ManagedTransferResult reports the exact published target. Changed is false
// only when the explicit skip policy found an existing destination.
type ManagedTransferResult struct {
	Destination string
	Changed     bool
}

type ManagedBatchMutationResult struct {
	Completed []string
	Changed   bool
}

// ManagedFileIdentity is the complete Linux stat identity used to bind an
// idempotency record to the exact regular file published by a managed
// mutation. It is intentionally comparable so callers can retain it without
// retaining an open descriptor or file contents.
type ManagedFileIdentity struct {
	Device              uint64
	Inode               uint64
	Mode                uint32
	Links               uint64
	Size                int64
	ModifiedSeconds     int64
	ModifiedNanoseconds int64
	ChangedSeconds      int64
	ChangedNanoseconds  int64
}

// ManagedMutationError reports that a namespace mutation happened before the
// requested operation completed. Callers must not retry such an operation as
// though nothing changed. DurabilityUnknown distinguishes an incomplete but
// fully synchronized operation from one whose final persistence is uncertain.
type ManagedMutationError struct {
	Operation         string
	Changed           bool
	DurabilityUnknown bool
	Err               error
}

func (e *ManagedMutationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Operation
	}
	if e.Operation == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Operation, e.Err)
}

func (e *ManagedMutationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func ManagedMutationChanged(err error) bool {
	changed, _ := aggregateManagedMutationState(err)
	return changed
}

func ManagedMutationDurabilityUnknown(err error) bool {
	_, durabilityUnknown := aggregateManagedMutationState(err)
	return durabilityUnknown
}

func aggregateManagedMutationState(err error) (changed, durabilityUnknown bool) {
	type pendingError struct {
		err   error
		depth int
	}
	stack := []pendingError{{err: err}}
	const maxMutationErrorNodes = 256
	const maxMutationErrorDepth = 64
	visited := 0
	truncated := false
	for len(stack) > 0 && visited < maxMutationErrorNodes {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		if current.err == nil {
			continue
		}
		if current.depth > maxMutationErrorDepth {
			truncated = true
			continue
		}
		visited++
		if mutationError, ok := current.err.(*ManagedMutationError); ok && mutationError != nil {
			changed = changed || mutationError.Changed
			durabilityUnknown = durabilityUnknown || mutationError.DurabilityUnknown
		}
		switch unwrapped := current.err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range unwrapped.Unwrap() {
				stack = append(stack, pendingError{err: child, depth: current.depth + 1})
			}
		case interface{ Unwrap() error }:
			stack = append(stack, pendingError{err: unwrapped.Unwrap(), depth: current.depth + 1})
		}
	}
	// Mutation metadata is security-sensitive: callers use a negative result
	// to decide whether an operation is safe to retry. A cyclic, pathologically
	// deep, or otherwise oversized error graph must therefore fail closed
	// instead of silently discarding state hidden beyond the traversal budget.
	if truncated || len(stack) > 0 {
		return true, true
	}
	return changed, durabilityUnknown
}

func managedChangedMutationError(operation string, durabilityUnknown bool, err error) error {
	if err == nil {
		return nil
	}
	if ManagedMutationChanged(err) && (!durabilityUnknown || ManagedMutationDurabilityUnknown(err)) {
		return err
	}
	return &ManagedMutationError{
		Operation:         operation,
		Changed:           true,
		DurabilityUnknown: durabilityUnknown || ManagedMutationDurabilityUnknown(err),
		Err:               err,
	}
}
