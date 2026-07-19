package filesecurity

import (
	"errors"
	"fmt"
	"testing"
)

type cyclicManagedTestError struct{}

func (*cyclicManagedTestError) Error() string { return "cycle" }
func (err *cyclicManagedTestError) Unwrap() error {
	return err
}

func TestParseManagedConflictStyleFailsClosed(t *testing.T) {
	for _, valid := range []ManagedConflictStyle{ManagedConflictSkip, ManagedConflictReplace, ManagedConflictRename} {
		parsed, err := ParseManagedConflictStyle(string(valid))
		if err != nil || parsed != valid {
			t.Fatalf("ParseManagedConflictStyle(%q) = %q, %v", valid, parsed, err)
		}
	}
	if parsed, err := ParseManagedConflictStyle("overwrite"); err != nil || parsed != ManagedConflictReplace {
		t.Fatalf("legacy overwrite alias = %q, %v", parsed, err)
	}
	for _, invalid := range []string{"", "overwrite-all", "SKIP", " skip "} {
		if _, err := ParseManagedConflictStyle(invalid); !errors.Is(err, ErrInvalidManagedConflictStyle) {
			t.Fatalf("ParseManagedConflictStyle(%q) error = %v", invalid, err)
		}
	}
}

func TestManagedMutationStateAggregatesJoinedErrorsInEitherOrder(t *testing.T) {
	unchanged := &ManagedMutationError{Operation: "cleanup", Changed: false, DurabilityUnknown: false, Err: errors.New("cleanup")}
	changed := &ManagedMutationError{Operation: "publish", Changed: true, DurabilityUnknown: true, Err: errors.New("publish")}
	for _, err := range []error{errors.Join(unchanged, changed), errors.Join(changed, unchanged)} {
		if !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
			t.Fatalf("joined mutation state was downgraded: %v", err)
		}
	}
}

func TestManagedChangedMutationErrorUpgradesUnchangedWrapper(t *testing.T) {
	unchanged := &ManagedMutationError{Operation: "cleanup", Changed: false, Err: errors.New("cleanup")}
	upgraded := managedChangedMutationError("published", true, unchanged)
	if !ManagedMutationChanged(upgraded) || !ManagedMutationDurabilityUnknown(upgraded) {
		t.Fatalf("upgraded mutation state = %v", upgraded)
	}
}

func TestManagedMutationStateFailsClosedWhenTraversalIsTruncated(t *testing.T) {
	deep := error(errors.New("deep"))
	for depth := 0; depth < 80; depth++ {
		deep = fmt.Errorf("level %d: %w", depth, deep)
	}
	for name, err := range map[string]error{
		"deep":  deep,
		"cycle": &cyclicManagedTestError{},
	} {
		t.Run(name, func(t *testing.T) {
			if !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
				t.Fatalf("truncated mutation graph did not fail closed: %v", err)
			}
		})
	}
}
