package service

import (
	"strings"
	"testing"
	"time"

	"github.com/moby/sys/mountinfo"
)

func TestValidateSambaConnectionFieldsRejectsMountOptionInjection(t *testing.T) {
	if err := ValidateSambaConnectionFields("alice", "correct horse battery staple", "nas.local", "445"); err != nil {
		t.Fatalf("safe connection rejected: %v", err)
	}
	for _, testCase := range []struct {
		username string
		password string
		host     string
		port     string
	}{
		{username: "alice,uid=0", password: "safe", host: "nas.local", port: "445"},
		{username: "alice", password: "secret,uid=0", host: "nas.local", port: "445"},
		{username: "alice", password: "secret\nuid=0", host: "nas.local", port: "445"},
		{username: "alice", password: "safe", host: "nas.local,port=1", port: "445"},
		{username: "alice", password: "safe", host: "nas local", port: "445"},
		{username: "alice", password: "safe", host: "nas.local", port: "0445"},
		{username: "alice", password: "safe", host: "nas.local", port: "1445"},
		{username: "alice", password: "safe", host: "nas.local", port: "65536"},
		{username: strings.Repeat("a", 256), password: "safe", host: "nas.local", port: "445"},
		{username: "alice", password: strings.Repeat("x", 1025), host: "nas.local", port: "445"},
	} {
		if err := ValidateSambaConnectionFields(testCase.username, testCase.password, testCase.host, testCase.port); err == nil {
			t.Errorf("unsafe connection unexpectedly accepted: %+v", testCase)
		}
	}
}

func TestSambaConnectionLifecycleLockSerializesMutations(t *testing.T) {
	releaseFirst := AcquireSambaConnectionLifecycle()
	released := false
	defer func() {
		if !released {
			releaseFirst()
		}
	}()

	secondAcquired := make(chan struct{})
	secondDone := make(chan struct{})
	secondReady := make(chan struct{})
	go func() {
		close(secondReady)
		releaseSecond := AcquireSambaConnectionLifecycle()
		close(secondAcquired)
		releaseSecond()
		close(secondDone)
	}()
	<-secondReady

	select {
	case <-secondAcquired:
		t.Fatal("second Samba lifecycle mutation entered while the first held the lock")
	case <-time.After(50 * time.Millisecond):
	}

	releaseFirst()
	released = true
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second Samba lifecycle mutation did not proceed after release")
	}
}

func TestValidateSambaMountEntriesRequiresPersistedMountID(t *testing.T) {
	mounts := []*mountinfo.Info{{
		ID:         731,
		FSType:     "cifs",
		Source:     "//nas.local/Media",
		Mountpoint: "/mnt/nas.local/Media",
	}}
	identity, mounted, err := inspectSambaMountEntries("/mnt/nas.local/Media", "nas.local", "Media", mounts)
	if err != nil || !mounted || identity.MountID != 731 {
		t.Fatalf("inspect identity = %+v, mounted = %v, error = %v", identity, mounted, err)
	}
	if matches, err := validateSambaMountEntries("/mnt/nas.local/Media", "nas.local", "Media", 731, mounts); err != nil || !matches {
		t.Fatalf("persisted mount identity rejected: matches=%v error=%v", matches, err)
	}
	if matches, err := validateSambaMountEntries("/mnt/nas.local/Media", "nas.local", "Media", 732, mounts); err == nil || matches {
		t.Fatalf("mismatched mount ID accepted: matches=%v error=%v", matches, err)
	}
}

func TestValidateSambaMountEntriesRejectsStackedMounts(t *testing.T) {
	correctMount := func(id int) *mountinfo.Info {
		return &mountinfo.Info{
			ID:         id,
			Mountpoint: "/mnt/nas.local/Media",
			FSType:     "cifs",
			Source:     "//nas.local/Media",
		}
	}
	mounts := []*mountinfo.Info{
		{ID: 1, Mountpoint: "/", FSType: "ext4", Source: "/dev/root"},
		correctMount(2),
		{ID: 3, Mountpoint: "/mnt/other", FSType: "cifs", Source: "//other/Media"},
		correctMount(4),
	}
	mounted, err := validateSambaMountEntries("/mnt/nas.local/Media", "nas.local", "Media", 2, mounts)
	if err == nil {
		t.Fatal("stacked Samba mounts unexpectedly accepted")
	}
	if mounted {
		t.Fatal("stacked Samba mounts reported as a unique identity")
	}
}

func TestFilterSambaMountableSharesDropsHiddenAndAdministrativeShares(t *testing.T) {
	filtered, err := FilterSambaMountableShares([]string{"Media", "IPC$", "ADMIN$", "C$", "print$", "Backups"}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(filtered, ",") != "Media,Backups" {
		t.Fatalf("filtered shares = %#v", filtered)
	}
	if _, err := FilterSambaMountableShares([]string{"IPC$", "ADMIN$", "C$"}, 64); err == nil {
		t.Fatal("all-hidden share list unexpectedly accepted")
	}
}

func TestSambaMountIDsRoundTripAndRejectInvalidRecords(t *testing.T) {
	encoded, err := EncodeSambaMountIDs(map[string]uint64{"Media": 12, "Backups": 34}, 64)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseSambaMountIDs(encoded, 64)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["Media"] != 12 || decoded["Backups"] != 34 {
		t.Fatalf("decoded mount IDs = %#v", decoded)
	}
	for _, invalid := range []string{`{"Media":0}`, `{"IPC$":12}`, `[]`, `{broken`} {
		if _, err := ParseSambaMountIDs(invalid, 64); err == nil {
			t.Fatalf("invalid mount IDs %q unexpectedly accepted", invalid)
		}
	}
}

func TestParseSambaDirectoriesIsBoundedAndUnambiguous(t *testing.T) {
	directories, err := ParseSambaDirectories("Media,Backups", 64)
	if err != nil {
		t.Fatalf("ParseSambaDirectories() error = %v", err)
	}
	if len(directories) != 2 || directories[0] != "Media" || directories[1] != "Backups" {
		t.Fatalf("directories = %#v", directories)
	}
	for _, value := range []string{"", "Media,Media", "Media,,Backups", "Media\nAdmin", `foo\bar`, " Media", "Media "} {
		if _, err := ParseSambaDirectories(value, 64); err == nil {
			t.Errorf("ParseSambaDirectories(%q) unexpectedly succeeded", value)
		}
	}
	tooMany := strings.TrimSuffix(strings.Repeat("Share,", 65), ",")
	if _, err := ParseSambaDirectories(tooMany, 64); err == nil {
		t.Fatal("oversized Samba directory list unexpectedly succeeded")
	}
}

func TestParsePersistedSambaConnectionQuarantinesLegacyOwnership(t *testing.T) {
	directories, all, port, legacy, err := ParsePersistedSambaConnection("Media,IPC$,ADMIN$,Backups", "", "", "", 64)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy || port != "445" || strings.Join(directories, ",") != "Media,Backups" || strings.Join(all, ",") != "Media,IPC$,ADMIN$,Backups" {
		t.Fatalf("legacy parse = directories %#v, all %#v, port %q, legacy %v", directories, all, port, legacy)
	}

	// Non-canonical ports and credentials are deliberately not promoted by the
	// parser. Startup mount validation quarantines them, while DELETE can still
	// use only the bounded host/path and mount-boundary preflight.
	_, _, port, legacy, err = ParsePersistedSambaConnection("IPC$", "1445", "", "", 64)
	if err != nil || !legacy || port != "1445" {
		t.Fatalf("legacy non-canonical port was not quarantinable: port=%q legacy=%v err=%v", port, legacy, err)
	}
	if err := ValidateSambaConnectionFields("", "bad,credential", "nas.local", port); err == nil {
		t.Fatal("legacy values unexpectedly qualified for trusted mount ownership")
	}
}

func TestParsePersistedSambaConnectionRejectsPartialOrUnsafeIdentity(t *testing.T) {
	for _, testCase := range []struct {
		directories string
		bootID      string
		mountIDs    string
	}{
		{directories: "Media", bootID: "boot-only"},
		{directories: "Media", mountIDs: `{"Media":7}`},
		{directories: "Media,,IPC$"},
		{directories: "../Media"},
	} {
		if _, _, _, _, err := ParsePersistedSambaConnection(testCase.directories, "445", testCase.bootID, testCase.mountIDs, 64); err == nil {
			t.Fatalf("unsafe persisted identity unexpectedly accepted: %+v", testCase)
		}
	}
	if err := ValidateLegacySambaHost("../nas"); err == nil {
		t.Fatal("unsafe legacy host unexpectedly accepted")
	}
}
