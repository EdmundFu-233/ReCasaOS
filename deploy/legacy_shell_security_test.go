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

func TestCasaOSSetupNeverOverwritesCurrentConfigWithLegacyConfig(t *testing.T) {
	for _, path := range []string{
		"build/scripts/setup/service.d/casaos/arch/setup-casaos.sh",
		"build/scripts/setup/service.d/casaos/debian/setup-casaos.sh",
		"build/scripts/setup/service.d/casaos/debian/bullseye/setup-casaos.sh",
		"build/scripts/setup/service.d/casaos/ubuntu/setup-casaos.sh",
		"build/scripts/setup/service.d/casaos/ubuntu/jammy/setup-casaos.sh",
	} {
		script := repositoryFile(t, path)
		currentGuard := strings.Index(script, `if [ ! -e "${CONF_FILE}" ]; then`)
		legacyGuard := strings.Index(script, `if [ -e "${OLD_CONF_PATH}" ] || [ -L "${OLD_CONF_PATH}" ]; then`)
		if currentGuard < 0 || legacyGuard < 0 || legacyGuard <= currentGuard {
			t.Errorf("%s must check that the current config is absent before considering the legacy config", path)
		}
		for _, required := range []string{
			"umask 077",
			`if [ -L "${CONF_FILE}" ] || { [ -e "${CONF_FILE}" ] && [ ! -f "${CONF_FILE}" ]; }; then`,
			`if [ ! -f "${OLD_CONF_PATH}" ] || [ -L "${OLD_CONF_PATH}" ]; then`,
			`if [ ! -f "${CONF_SOURCE}" ] || [ -L "${CONF_SOURCE}" ]; then`,
			`install -o root -g root -m 0600 -- "${CONF_SOURCE}" "${CONF_FILE}"`,
			`chown root:root -- "${CONF_FILE}"`,
			`chmod 0600 -- "${CONF_FILE}"`,
			"rm -f -- /etc/systemd/system/casaos.service",
		} {
			if count := strings.Count(script, required); count != 1 {
				t.Errorf("%s contains safe setup operation %q %d times, want exactly once", path, required, count)
			}
		}
		for _, forbidden := range []string{
			`cp "${OLD_CONF_PATH}" "${CONF_FILE}"`,
			`cp -v "${CONF_FILE_SAMPLE}" "${CONF_FILE}"`,
			`install -o root -g root -m 0600 "${OLD_CONF_PATH}" "${CONF_FILE}"`,
			`install -o root -g root -m 0600 "${CONF_FILE_SAMPLE}" "${CONF_FILE}"`,
			"rm -rf /etc/systemd/system/casaos.service",
		} {
			if strings.Contains(script, forbidden) {
				t.Errorf("%s still contains unsafe setup operation %q", path, forbidden)
			}
		}
	}
}
