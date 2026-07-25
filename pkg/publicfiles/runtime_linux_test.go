//go:build linux

package publicfiles

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

const safeServiceRuntimeCgroup = "0::/system.slice/recasaos-public-files.service\n"

func TestValidateServiceRuntimeStatusAcceptsReviewedBoundary(t *testing.T) {
	if err := validateServiceRuntimeStatus([]byte(safeServiceRuntimeStatus), 62001, 62001); err != nil {
		t.Fatal(err)
	}
}

func TestValidateServiceRuntimeCgroupAcceptsReviewedBoundary(t *testing.T) {
	if err := validateServiceRuntimeCgroup([]byte(safeServiceRuntimeCgroup)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateServiceRuntimeCgroupRejectsWeakenedBoundary(t *testing.T) {
	tests := map[string]string{
		"v1 hierarchy":     "2:memory:/system.slice/recasaos-public-files.service\n",
		"hybrid hierarchy": safeServiceRuntimeCgroup + "2:memory:/system.slice/recasaos-public-files.service\n",
		"wrong unit":       "0::/system.slice/casaos.service\n",
		"wrong slice":      "0::/other.slice/recasaos-public-files.service\n",
		"delegated user slice": "0::/user.slice/user-62001.slice/user@62001.service/" +
			"app.slice/recasaos-public-files.service\n",
		"deceptive suffix":   "0::/system.slice/not-recasaos-public-files.service\n",
		"root cgroup":        "0::/\n",
		"missing newline":    strings.TrimSuffix(safeServiceRuntimeCgroup, "\n"),
		"extra blank line":   safeServiceRuntimeCgroup + "\n",
		"unexpected control": "0::/system.slice/recasaos-public-files.service\x00\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceRuntimeCgroup([]byte(content)); err == nil {
				t.Fatal("weakened cgroup boundary was accepted")
			}
		})
	}
}

func TestValidateServiceRuntimeCgroupLimitDirectoryMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata unix.Stat_t
		wantErr  bool
	}{
		{
			name:     "root owned read only",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o555},
		},
		{
			name:     "root owner writable",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o755},
		},
		{
			name:     "group writable",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o775},
			wantErr:  true,
		},
		{
			name:     "other writable",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o757},
			wantErr:  true,
		},
		{
			name:     "world writable",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o777},
			wantErr:  true,
		},
		{
			name:     "sticky world writable",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o1777},
			wantErr:  true,
		},
		{
			name:     "service owned",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o555, Uid: 62001},
			wantErr:  true,
		},
		{
			name:     "service group",
			metadata: unix.Stat_t{Mode: unix.S_IFDIR | 0o555, Gid: 62001},
			wantErr:  true,
		},
		{
			name:     "regular file",
			metadata: unix.Stat_t{Mode: unix.S_IFREG | 0o444},
			wantErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateServiceRuntimeCgroupLimitDirectoryMetadata(test.metadata)
			if test.wantErr && err == nil {
				t.Fatal("unsafe cgroup limit directory metadata was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("safe cgroup limit directory metadata was rejected: %v", err)
			}
		})
	}
}

func TestValidateServiceRuntimeCgroupLimitValueAcceptsReviewedBoundary(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     serviceRuntimeMemoryMaxFile,
			content:  serviceRuntimeMemoryMaxValue + "\n",
			expected: serviceRuntimeMemoryMaxValue,
		},
		{
			name:     serviceRuntimeMemorySwapMaxFile,
			content:  serviceRuntimeMemorySwapMaxValue + "\n",
			expected: serviceRuntimeMemorySwapMaxValue,
		},
		{
			name:     serviceRuntimeProcessLimitFile,
			content:  serviceRuntimeProcessLimitValue + "\n",
			expected: serviceRuntimeProcessLimitValue,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateServiceRuntimeCgroupLimitValue(
				test.name,
				[]byte(test.content),
				test.expected,
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateServiceRuntimeCgroupLimitMountAcceptsReviewedBoundary(t *testing.T) {
	const mountInfo = "" +
		"20 1 0:1 / / ro,relatime - ext4 /dev/root ro\n" +
		"42 20 0:28 /system.slice/recasaos-public-files.service/memory.max " +
		"/run/recasaos-cgroup/memory.max ro,nosuid,nodev,noexec,relatime - " +
		"cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
	if err := validateServiceRuntimeCgroupLimitMount(
		[]byte(mountInfo),
		42,
		serviceRuntimeMemoryMaxFile,
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateServiceRuntimeCgroupLimitMountRejectsWeakenedBoundary(t *testing.T) {
	const safeLine = "42 20 0:28 /system.slice/recasaos-public-files.service/memory.max " +
		"/run/recasaos-cgroup/memory.max ro,nosuid,nodev,noexec,relatime - " +
		"cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
	tests := map[string]string{
		"missing mount": "20 1 0:1 / / ro,relatime - ext4 /dev/root ro\n",
		"wrong root": strings.Replace(
			safeLine,
			"/system.slice/recasaos-public-files.service/memory.max",
			"/system.slice/decoy.service/memory.max",
			1,
		),
		"writable mount": strings.Replace(
			safeLine,
			" ro,nosuid",
			" rw,nosuid",
			1,
		),
		"wrong filesystem": strings.Replace(
			safeLine,
			" - cgroup2 ",
			" - tmpfs ",
			1,
		),
		"duplicate mount": safeLine + safeLine,
		"missing newline": strings.TrimSuffix(safeLine, "\n"),
		"malformed line":  safeLine + "malformed\n",
		"unexpected control": strings.Replace(
			safeLine,
			"/run/recasaos-cgroup/memory.max",
			"/run/recasaos-cgroup/memory.max\x00",
			1,
		),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceRuntimeCgroupLimitMount(
				[]byte(content),
				42,
				serviceRuntimeMemoryMaxFile,
			); err == nil {
				t.Fatal("weakened cgroup limit mount was accepted")
			}
		})
	}

	t.Run("wrong mount id", func(t *testing.T) {
		if err := validateServiceRuntimeCgroupLimitMount(
			[]byte(safeLine),
			43,
			serviceRuntimeMemoryMaxFile,
		); err == nil {
			t.Fatal("wrong cgroup limit mount identity was accepted")
		}
	})
}

func TestValidateServiceRuntimeCgroupLimitValueRejectsWeakenedBoundary(t *testing.T) {
	tests := map[string]string{
		"unlimited":          "max\n",
		"larger":             "536870913\n",
		"leading space":      " 536870912\n",
		"trailing space":     "536870912 \n",
		"missing newline":    "536870912",
		"extra newline":      "536870912\n\n",
		"unexpected control": "536870912\x00\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceRuntimeCgroupLimitValue(
				serviceRuntimeMemoryMaxFile,
				[]byte(content),
				serviceRuntimeMemoryMaxValue,
			); err == nil {
				t.Fatal("weakened cgroup limit was accepted")
			}
		})
	}
}

func TestDisableServiceRuntimeDumpability(t *testing.T) {
	const helperEnvironment = "RECASAOS_TEST_DISABLE_RUNTIME_DUMPABILITY"
	if os.Getenv(helperEnvironment) == "1" {
		if err := disableServiceRuntimeDumpability(); err != nil {
			t.Fatal(err)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestDisableServiceRuntimeDumpability$")
	command.Env = []string{
		helperEnvironment + "=1",
		"GOTRACEBACK=none",
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("dumpability helper failed: %v: %s", err, output)
	}
}

func TestValidateRuntimeIDsAcceptsFullUint32Range(t *testing.T) {
	const highRuntimeID uint64 = (1 << 32) - 2
	const encoded = "4294967294 4294967294 4294967294 4294967294"
	if err := validateRuntimeIDs("Uid", encoded, highRuntimeID); err != nil {
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
		{name: "high uid", status: strings.Replace(safeServiceRuntimeStatus, "Uid:\t62001\t62001\t62001\t62001", "Uid:\t4294967294\t4294967294\t4294967294\t4294967294", 1), uid: 62001, gid: 62001},
		{name: "high gid", status: strings.Replace(safeServiceRuntimeStatus, "Gid:\t62001\t62001\t62001\t62001", "Gid:\t4294967294\t4294967294\t4294967294\t4294967294", 1), uid: 62001, gid: 62001},
		{name: "high supplementary group", status: strings.Replace(safeServiceRuntimeStatus, "Groups:\t62001", "Groups:\t4294967294", 1), uid: 62001, gid: 62001},
		{name: "overflowing uid", status: strings.Replace(safeServiceRuntimeStatus, "Uid:\t62001\t62001\t62001\t62001", "Uid:\t4294967296\t4294967296\t4294967296\t4294967296", 1), uid: 62001, gid: 62001},
		{name: "negative supplementary group", status: strings.Replace(safeServiceRuntimeStatus, "Groups:\t62001", "Groups:\t-1", 1), uid: 62001, gid: 62001},
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
