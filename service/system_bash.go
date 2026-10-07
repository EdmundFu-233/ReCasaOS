package service

import "os/exec"

// onlyExec: CasaOS-Common command.OnlyExec without hardcoded /bin/bash (absent on NixOS, minimal images)
func onlyExec(cmdStr string) (string, error) {
	cmd := exec.Command("bash", "-c", cmdStr)
	buf, err := cmd.CombinedOutput()
	return string(buf), err
}
