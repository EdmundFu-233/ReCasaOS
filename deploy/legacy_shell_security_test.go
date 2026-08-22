package deploy

import (
	"strings"
	"testing"
)

func TestLegacyUSBMountHelpersNeverEvaluateDeviceMetadata(t *testing.T) {
	for _, path := range []string{
		"build/sysroot/usr/share/casaos/shell/usb-mount.sh",
		"build/sysroot/usr/share/casaos/shell/helper.sh",
	} {
		script := repositoryFile(t, path)
		for _, forbidden := range []string{
			"eval $(blkid",
			"blkid -o udev",
			"ID_FS_LABEL",
			"ID_FS_LABEL_ENC",
		} {
			if strings.Contains(script, forbidden) {
				t.Errorf("%s still interprets attacker-controlled device metadata through %q", path, forbidden)
			}
		}
		for _, required := range []string{
			`ID_FS_TYPE="$(blkid -s TYPE -o value -- "$DEVICE")"`,
			`case "${ID_FS_TYPE}" in`,
		} {
			if !strings.Contains(script, required) {
				t.Errorf("%s is missing the bounded filesystem-type check %q", path, required)
			}
		}
	}
}
