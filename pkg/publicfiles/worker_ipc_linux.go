//go:build linux

package publicfiles

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const storageWorkerMaxRights = 2

func newStorageWorkerSocketPair() (*net.UnixConn, *os.File, error) {
	descriptors, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	parentFile := os.NewFile(uintptr(descriptors[0]), "public-files-worker-parent")
	childFile := os.NewFile(uintptr(descriptors[1]), "public-files-worker-child")
	connection, err := net.FileConn(parentFile)
	closeErr := parentFile.Close()
	if err != nil || closeErr != nil {
		if connection != nil {
			_ = connection.Close()
		}
		_ = childFile.Close()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, closeErr
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		_ = childFile.Close()
		return nil, nil, errStorageProtocol
	}
	return unixConnection, childFile, nil
}

func storageWorkerConnectionFromFD(fd uintptr) (*net.UnixConn, error) {
	file := os.NewFile(fd, "public-files-worker-ipc")
	if file == nil {
		return nil, errStorageProtocol
	}
	connection, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if connection != nil {
			_ = connection.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, closeErr
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errStorageProtocol
	}
	return unixConnection, nil
}

func validateStorageWorkerConnection(connection *net.UnixConn, expectedPeerPID int) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errStorageProtocol
	}
	var validationErr error
	if err := raw.Control(func(fd uintptr) {
		socketType, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || socketType != unix.SOCK_SEQPACKET {
			validationErr = errStorageProtocol
			return
		}
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil ||
			peer.Pid != int32(expectedPeerPID) ||
			peer.Uid != uint32(os.Geteuid()) ||
			peer.Gid != uint32(os.Getegid()) {
			validationErr = errStorageProtocol
		}
	}); err != nil {
		return errStorageProtocol
	}
	return validationErr
}

func sendStorageWorkerFrame(
	connection *net.UnixConn,
	frame storageWorkerFrame,
	rights []int,
	deadline time.Time,
) error {
	if len(rights) > storageWorkerMaxRights {
		return errStorageProtocol
	}
	packet, err := marshalStorageWorkerFrame(frame)
	if err != nil {
		return err
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return errStorageProtocol
	}
	var outOfBand []byte
	if len(rights) != 0 {
		outOfBand = unix.UnixRights(rights...)
	}
	written, outOfBandWritten, err := connection.WriteMsgUnix(packet, outOfBand, nil)
	if err != nil {
		return err
	}
	if written != len(packet) || outOfBandWritten != len(outOfBand) {
		return errStorageProtocol
	}
	return nil
}

func receiveStorageWorkerFrame(
	connection *net.UnixConn,
	deadline time.Time,
) (storageWorkerFrame, []int, error) {
	var zero storageWorkerFrame
	if err := connection.SetReadDeadline(deadline); err != nil {
		return zero, nil, errStorageProtocol
	}
	packet := make([]byte, storageWorkerHeaderBytes+storageWorkerMaxFramePayload+1)
	outOfBand := make([]byte, unix.CmsgSpace(storageWorkerMaxRights*4))

	raw, err := connection.SyscallConn()
	if err != nil {
		return zero, nil, errStorageProtocol
	}
	var (
		packetBytes    int
		outOfBandBytes int
		messageFlags   int
		receiveErr     error
	)
	if err := raw.Read(func(fd uintptr) bool {
		packetBytes, outOfBandBytes, messageFlags, _, receiveErr = unix.Recvmsg(
			int(fd),
			packet,
			outOfBand,
			unix.MSG_CMSG_CLOEXEC,
		)
		if errors.Is(receiveErr, unix.EAGAIN) || errors.Is(receiveErr, unix.EWOULDBLOCK) {
			receiveErr = nil
			return false
		}
		return true
	}); err != nil {
		return zero, nil, err
	}
	rights, rightsErr := parseStorageWorkerRights(outOfBand[:outOfBandBytes])
	if receiveErr != nil {
		closeStorageWorkerRights(rights)
		return zero, nil, receiveErr
	}
	if messageFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 ||
		packetBytes == 0 ||
		packetBytes > storageWorkerHeaderBytes+storageWorkerMaxFramePayload {
		closeStorageWorkerRights(rights)
		return zero, nil, errStorageProtocol
	}
	if rightsErr != nil {
		return zero, nil, rightsErr
	}
	frame, err := parseStorageWorkerFrame(packet[:packetBytes])
	if err != nil {
		closeStorageWorkerRights(rights)
		return zero, nil, err
	}
	return frame, rights, nil
}

func parseStorageWorkerRights(outOfBand []byte) ([]int, error) {
	if len(outOfBand) == 0 {
		return nil, nil
	}
	messages, parseErr := unix.ParseSocketControlMessage(outOfBand)
	if len(messages) == 0 {
		return nil, errStorageProtocol
	}
	var rights []int
	for index := range messages {
		parsed, err := unix.ParseUnixRights(&messages[index])
		if err != nil || len(parsed) == 0 {
			closeStorageWorkerRights(rights)
			return nil, errStorageProtocol
		}
		rights = append(rights, parsed...)
		if len(rights) > storageWorkerMaxRights {
			closeStorageWorkerRights(rights)
			return nil, errStorageProtocol
		}
	}
	if parseErr != nil {
		closeStorageWorkerRights(rights)
		return nil, errStorageProtocol
	}
	return rights, nil
}

func closeStorageWorkerRights(rights []int) {
	for _, fd := range rights {
		_ = unix.Close(fd)
	}
}
