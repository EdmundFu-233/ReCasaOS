//go:build linux

package publicfiles

import (
	"strings"
	"testing"
)

const safeServiceRuntimeStatus = `Name:	recasaos-public
Umask:	0077
Uid:	62001	62001	62001	62001
Gid:	62001	62001	62001	62001
Groups:	62001
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
Seccomp:	2
`

func TestValidateServiceRuntimeStatusAcceptsReviewedBoundary(t *testing.T) {
	if err := validateServiceRuntimeStatus([]byte(safeServiceRuntimeStatus), 62001, 62001); err != nil {
		t.Fatal(err)
	}
}

func TestValidateServiceRuntimeStatusRejectsWeakenedProcess(t *testing.T) {
	tests := []struct {
		name   string
		status string
		uid    int
		gid    int
	}{
		{name: "root uid", status: strings.Replace(safeServiceRuntimeStatus, "Uid:\t62001\t62001\t62001\t62001", "Uid:\t0\t0\t0\t0", 1), uid: 0, gid: 62001},
		{name: "root gid", status: strings.Replace(safeServiceRuntimeStatus, "Gid:\t62001\t62001\t62001\t62001", "Gid:\t0\t0\t0\t0", 1), uid: 62001, gid: 0},
		{name: "saved uid differs", status: strings.Replace(safeServiceRuntimeStatus, "Uid:\t62001\t62001\t62001\t62001", "Uid:\t62001\t62001\t0\t62001", 1), uid: 62001, gid: 62001},
		{name: "supplementary group", status: strings.Replace(safeServiceRuntimeStatus, "Groups:\t62001", "Groups:\t62001 44", 1), uid: 62001, gid: 62001},
		{name: "broad umask", status: strings.Replace(safeServiceRuntimeStatus, "Umask:\t0077", "Umask:\t0022", 1), uid: 62001, gid: 62001},
		{name: "effective capability", status: strings.Replace(safeServiceRuntimeStatus, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1), uid: 62001, gid: 62001},
		{name: "bounding capability", status: strings.Replace(safeServiceRuntimeStatus, "CapBnd:\t0000000000000000", "CapBnd:\t00000000a80425fb", 1), uid: 62001, gid: 62001},
		{name: "new privileges permitted", status: strings.Replace(safeServiceRuntimeStatus, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), uid: 62001, gid: 62001},
		{name: "seccomp disabled", status: strings.Replace(safeServiceRuntimeStatus, "Seccomp:\t2", "Seccomp:\t0", 1), uid: 62001, gid: 62001},
		{name: "missing field", status: strings.Replace(safeServiceRuntimeStatus, "CapAmb:\t0000000000000000\n", "", 1), uid: 62001, gid: 62001},
		{name: "duplicate field", status: safeServiceRuntimeStatus + "CapEff:\t0000000000000000\n", uid: 62001, gid: 62001},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateServiceRuntimeStatus([]byte(test.status), test.uid, test.gid); err == nil {
				t.Fatal("weakened runtime was accepted")
			}
		})
	}
}
