//go:build linux

package publicfiles

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseStorageWorkerVirtualMemory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  []byte
		pageSize uint64
		want     uint64
	}{
		{
			name:     "current hosted runner evidence with 4 KiB pages",
			content:  []byte("316132 2278 980 14 0 334 0\n"),
			pageSize: 4 << 10,
			want:     1294876672,
		},
		{
			name:     "16 KiB pages",
			content:  []byte("17 16 15 14 13 12 11\n"),
			pageSize: 16 << 10,
			want:     17 * 16 << 10,
		},
		{
			name:     "64 KiB pages and tab separators",
			content:  []byte("9\t8\t7\t6\t5\t4\t3\n"),
			pageSize: 64 << 10,
			want:     9 * 64 << 10,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseStorageWorkerVirtualMemory(test.content, test.pageSize)
			if err != nil {
				t.Fatalf("parseStorageWorkerVirtualMemory() error = %v", err)
			}
			if got != test.want {
				t.Fatalf(
					"parseStorageWorkerVirtualMemory() = %d, want %d",
					got,
					test.want,
				)
			}
		})
	}
}

func TestParseStorageWorkerVirtualMemoryRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  []byte
		pageSize uint64
	}{
		{name: "zero page size", content: []byte("1 1 1 1 1 1 1\n")},
		{name: "empty", pageSize: 4 << 10},
		{name: "missing newline", content: []byte("1 1 1 1 1 1 1"), pageSize: 4 << 10},
		{name: "multiple lines", content: []byte("1 1 1 1 1 1 1\n2\n"), pageSize: 4 << 10},
		{name: "carriage return", content: []byte("1 1 1 1 1 1 1\r\n"), pageSize: 4 << 10},
		{name: "embedded NUL", content: []byte("1 1 1\x001 1 1 1\n"), pageSize: 4 << 10},
		{name: "too few fields", content: []byte("1 1 1 1 1 1\n"), pageSize: 4 << 10},
		{name: "too many fields", content: []byte("1 1 1 1 1 1 1 1\n"), pageSize: 4 << 10},
		{name: "signed field", content: []byte("+1 1 1 1 1 1 1\n"), pageSize: 4 << 10},
		{name: "negative field", content: []byte("-1 1 1 1 1 1 1\n"), pageSize: 4 << 10},
		{name: "nonnumeric field", content: []byte("1 1 x 1 1 1 1\n"), pageSize: 4 << 10},
		{name: "zero virtual pages", content: []byte("0 1 1 1 1 1 1\n"), pageSize: 4 << 10},
		{
			name:     "virtual page multiplication overflow",
			content:  []byte("18446744073709551615 1 1 1 1 1 1\n"),
			pageSize: 4 << 10,
		},
		{
			name:     "secondary field overflow",
			content:  []byte("1 18446744073709551616 1 1 1 1 1\n"),
			pageSize: 4 << 10,
		},
		{
			name:     "exceeds bounded proc input",
			content:  append([]byte("1 1 1 1 1 1 1 "), make([]byte, storageWorkerStatmMaxBytes)...),
			pageSize: 4 << 10,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseStorageWorkerVirtualMemory(
				test.content,
				test.pageSize,
			); !errors.Is(err, errStorageProtocol) {
				t.Fatalf(
					"parseStorageWorkerVirtualMemory() error = %v, want errStorageProtocol",
					err,
				)
			}
		})
	}
}

func TestCalculateStorageWorkerAddressSpaceLimit(t *testing.T) {
	t.Parallel()

	const hostedRunnerBaseline = uint64(1294876672)
	got, err := calculateStorageWorkerAddressSpaceLimit(
		hostedRunnerBaseline,
		4<<10,
	)
	if err != nil {
		t.Fatalf("calculateStorageWorkerAddressSpaceLimit() error = %v", err)
	}
	want := hostedRunnerBaseline + storageWorkerAddressSpaceHeadroom
	if got != want {
		t.Fatalf(
			"calculateStorageWorkerAddressSpaceLimit() = %d, want %d",
			got,
			want,
		)
	}
	if got <= 1<<30 {
		t.Fatalf("dynamic address-space limit = %d, want above obsolete 1 GiB limit", got)
	}
}

func TestCalculateStorageWorkerAddressSpaceLimitAcceptsReviewedPageSizes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		pageSize uint64
	}{
		{name: "4 KiB pages", pageSize: 4 << 10},
		{name: "16 KiB pages", pageSize: 16 << 10},
		{name: "64 KiB pages", pageSize: 64 << 10},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := storageWorkerAddressSpaceCeiling -
				storageWorkerAddressSpaceHeadroom
			got, err := calculateStorageWorkerAddressSpaceLimit(
				baseline,
				test.pageSize,
			)
			if err != nil {
				t.Fatalf("calculateStorageWorkerAddressSpaceLimit() error = %v", err)
			}
			if got != storageWorkerAddressSpaceCeiling {
				t.Fatalf(
					"calculateStorageWorkerAddressSpaceLimit() = %d, want ceiling %d",
					got,
					storageWorkerAddressSpaceCeiling,
				)
			}
		})
	}
}

func TestCalculateStorageWorkerAddressSpaceLimitRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		current  uint64
		pageSize uint64
	}{
		{name: "zero current", pageSize: 4 << 10},
		{name: "zero page size", current: 4 << 10},
		{name: "unaligned current", current: 4097, pageSize: 4 << 10},
		{name: "unreviewed page size", current: 6 << 10, pageSize: 3 << 10},
		{
			name:     "target exceeds portable ceiling",
			current:  storageWorkerAddressSpaceCeiling - storageWorkerAddressSpaceHeadroom + 4<<10,
			pageSize: 4 << 10,
		},
		{name: "addition overflow", current: ^uint64(0), pageSize: 4 << 10},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := calculateStorageWorkerAddressSpaceLimit(
				test.current,
				test.pageSize,
			); !errors.Is(err, errStorageProtocol) {
				t.Fatalf(
					"calculateStorageWorkerAddressSpaceLimit() error = %v, want errStorageProtocol",
					err,
				)
			}
		})
	}
}

func TestValidateStorageWorkerInheritedAddressSpaceLimit(t *testing.T) {
	t.Parallel()

	target := uint64(1536 << 20)
	tests := []struct {
		name      string
		inherited unix.Rlimit
		wantError bool
	}{
		{
			name:      "unlimited",
			inherited: unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		},
		{
			name:      "exact",
			inherited: unix.Rlimit{Cur: target, Max: target},
		},
		{
			name:      "soft below target",
			inherited: unix.Rlimit{Cur: target - 1, Max: target},
			wantError: true,
		},
		{
			name:      "hard below target",
			inherited: unix.Rlimit{Cur: target - 1, Max: target - 1},
			wantError: true,
		},
		{
			name:      "invalid soft above hard",
			inherited: unix.Rlimit{Cur: target + 1, Max: target},
			wantError: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateStorageWorkerInheritedAddressSpaceLimit(
				test.inherited,
				target,
			)
			if test.wantError && !errors.Is(err, errStorageProtocol) {
				t.Fatalf("validation error = %v, want errStorageProtocol", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestValidateStorageWorkerAppliedAddressSpaceLimit(t *testing.T) {
	t.Parallel()

	target := uint64(1536 << 20)
	tests := []struct {
		name      string
		applied   unix.Rlimit
		current   uint64
		wantError bool
	}{
		{
			name:    "reviewed reserve",
			applied: unix.Rlimit{Cur: target, Max: target},
			current: target - storageWorkerAddressSpaceMinimumReserve,
		},
		{
			name:      "soft mismatch",
			applied:   unix.Rlimit{Cur: target - 1, Max: target},
			current:   target - storageWorkerAddressSpaceMinimumReserve,
			wantError: true,
		},
		{
			name:      "hard mismatch",
			applied:   unix.Rlimit{Cur: target, Max: target + 1},
			current:   target - storageWorkerAddressSpaceMinimumReserve,
			wantError: true,
		},
		{
			name:      "current exceeds target",
			applied:   unix.Rlimit{Cur: target, Max: target},
			current:   target + 1,
			wantError: true,
		},
		{
			name:      "reserve below minimum",
			applied:   unix.Rlimit{Cur: target, Max: target},
			current:   target - storageWorkerAddressSpaceMinimumReserve + 1,
			wantError: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateStorageWorkerAppliedAddressSpaceLimit(
				test.applied,
				target,
				test.current,
			)
			if test.wantError && !errors.Is(err, errStorageProtocol) {
				t.Fatalf("validation error = %v, want errStorageProtocol", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}
