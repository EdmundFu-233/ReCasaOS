//go:build linux && !recasaos_publicfiles_systemd_test

package publicfiles

func holdStorageFileWorkerForSystemdTest(string, int64) error {
	return nil
}
