package publicfiles

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

const (
	storageWorkerProtocolVersion uint16 = 1
	storageWorkerHeaderBytes            = 24
	storageWorkerMaxFramePayload        = 60 << 10
	// A legal directory can contain 1,000 255-byte names. Go's JSON encoder
	// expands HTML-sensitive filename bytes to six-byte escapes, so 2 MiB is a
	// reviewed bound that preserves the existing directory-entry contract.
	storageWorkerMaxListPayload = 2 << 20
	storageWorkerMaxReadBytes   = storageWorkerMaxFramePayload
)

var storageWorkerMagic = [4]byte{'R', 'C', 'F', 'W'}

type storageWorkerOpcode uint16

const (
	storageWorkerBootstrapRequest storageWorkerOpcode = iota + 1
	storageWorkerBootstrapResponse
	storageWorkerListRequest
	storageWorkerListResponse
	storageWorkerOpenRequest
	storageWorkerOpenResponse
	storageWorkerReadRequest
	storageWorkerReadResponse
	storageWorkerCloseRequest
	storageWorkerCloseResponse
)

type storageWorkerStatus uint16

const (
	storageWorkerStatusOK storageWorkerStatus = iota
	storageWorkerStatusHidden
	storageWorkerStatusEntryLimit
	storageWorkerStatusInvalid
	storageWorkerStatusInternal
	storageWorkerStatusEOF
	storageWorkerStatusUnsupported
)

const storageWorkerFlagMore uint16 = 1

type storageWorkerFrame struct {
	opcode    storageWorkerOpcode
	requestID uint64
	status    storageWorkerStatus
	flags     uint16
	payload   []byte
}

type storageBootstrapRequest struct {
	RootPath     string `json:"root_path"`
	VerifierPath string `json:"verifier_path"`
}

type storageBootstrapResponse struct {
	Verifier       [32]byte
	MountID        uint64
	FilesystemType uint32
}

type storageListRequest struct {
	Path           string `json:"path"`
	MaxEntries     int    `json:"max_entries"`
	MountID        uint64 `json:"mount_id"`
	FilesystemType uint32 `json:"filesystem_type"`
}

type storageOpenRequest struct {
	Path           string `json:"path"`
	MountID        uint64 `json:"mount_id"`
	FilesystemType uint32 `json:"filesystem_type"`
}

type storageOpenResponse struct {
	Size            int64
	ModTimeUnixNano int64
}

type storageReadRequest struct {
	Offset int64
	Length uint32
}

func marshalStorageWorkerFrame(frame storageWorkerFrame) ([]byte, error) {
	if !validStorageWorkerFrameHeader(frame) ||
		len(frame.payload) > storageWorkerMaxFramePayload {
		return nil, errStorageProtocol
	}
	packet := make([]byte, storageWorkerHeaderBytes+len(frame.payload))
	copy(packet[:4], storageWorkerMagic[:])
	binary.BigEndian.PutUint16(packet[4:6], storageWorkerProtocolVersion)
	binary.BigEndian.PutUint16(packet[6:8], uint16(frame.opcode))
	binary.BigEndian.PutUint64(packet[8:16], frame.requestID)
	binary.BigEndian.PutUint16(packet[16:18], uint16(frame.status))
	binary.BigEndian.PutUint16(packet[18:20], frame.flags)
	binary.BigEndian.PutUint32(packet[20:24], uint32(len(frame.payload)))
	copy(packet[storageWorkerHeaderBytes:], frame.payload)
	return packet, nil
}

func parseStorageWorkerFrame(packet []byte) (storageWorkerFrame, error) {
	var frame storageWorkerFrame
	if len(packet) < storageWorkerHeaderBytes ||
		!bytes.Equal(packet[:4], storageWorkerMagic[:]) ||
		binary.BigEndian.Uint16(packet[4:6]) != storageWorkerProtocolVersion {
		return frame, errStorageProtocol
	}
	payloadLength := int(binary.BigEndian.Uint32(packet[20:24]))
	if payloadLength > storageWorkerMaxFramePayload ||
		len(packet) != storageWorkerHeaderBytes+payloadLength {
		return frame, errStorageProtocol
	}
	frame.opcode = storageWorkerOpcode(binary.BigEndian.Uint16(packet[6:8]))
	frame.requestID = binary.BigEndian.Uint64(packet[8:16])
	frame.status = storageWorkerStatus(binary.BigEndian.Uint16(packet[16:18]))
	frame.flags = binary.BigEndian.Uint16(packet[18:20])
	frame.payload = append([]byte(nil), packet[storageWorkerHeaderBytes:]...)
	if !validStorageWorkerFrameHeader(frame) {
		return storageWorkerFrame{}, errStorageProtocol
	}
	return frame, nil
}

func validStorageWorkerFrameHeader(frame storageWorkerFrame) bool {
	return frame.opcode >= storageWorkerBootstrapRequest &&
		frame.opcode <= storageWorkerCloseResponse &&
		frame.requestID != 0 &&
		frame.status <= storageWorkerStatusUnsupported &&
		frame.flags&^storageWorkerFlagMore == 0
}

func marshalStorageWorkerJSON(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > storageWorkerMaxFramePayload {
		return nil, errStorageProtocol
	}
	return payload, nil
}

func unmarshalStorageWorkerJSON(payload []byte, value any) error {
	if len(payload) == 0 || len(payload) > storageWorkerMaxFramePayload {
		return errStorageProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errStorageProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errStorageProtocol
	}
	return nil
}

func decodeStorageWorkerEntries(payload []byte, maxEntries int) ([]Entry, error) {
	if len(payload) == 0 || len(payload) > storageWorkerMaxListPayload {
		return nil, errStorageProtocol
	}
	var entries []Entry
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, errStorageProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errStorageProtocol
	}
	if len(entries) > maxEntries {
		return nil, errStorageProtocol
	}
	for _, entry := range entries {
		if !isSafeVisibleName(entry.Name) ||
			entry.Name == "." ||
			entry.Name == ".." ||
			strings.HasPrefix(entry.Name, ".") ||
			strings.Contains(entry.Name, `\`) ||
			entry.Name != path.Base(entry.Name) ||
			entry.Size < 0 ||
			(entry.Type != "file" && entry.Type != "directory") ||
			(entry.Type == "directory" && entry.Size != 0) {
			return nil, errStorageProtocol
		}
	}
	return entries, nil
}

func marshalStorageBootstrapResponse(response storageBootstrapResponse) []byte {
	payload := make([]byte, 44)
	copy(payload[:32], response.Verifier[:])
	binary.BigEndian.PutUint64(payload[32:40], response.MountID)
	binary.BigEndian.PutUint32(payload[40:44], response.FilesystemType)
	return payload
}

func parseStorageBootstrapResponse(payload []byte) (storageBootstrapResponse, error) {
	var response storageBootstrapResponse
	if len(payload) != 44 {
		return response, errStorageProtocol
	}
	copy(response.Verifier[:], payload[:32])
	response.MountID = binary.BigEndian.Uint64(payload[32:40])
	response.FilesystemType = binary.BigEndian.Uint32(payload[40:44])
	if response.MountID == 0 {
		return storageBootstrapResponse{}, errStorageProtocol
	}
	return response, nil
}

func marshalStorageOpenResponse(response storageOpenResponse) []byte {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload[:8], uint64(response.Size))
	binary.BigEndian.PutUint64(payload[8:16], uint64(response.ModTimeUnixNano))
	return payload
}

func parseStorageOpenResponse(payload []byte) (storageOpenResponse, error) {
	if len(payload) != 16 {
		return storageOpenResponse{}, errStorageProtocol
	}
	response := storageOpenResponse{
		Size:            int64(binary.BigEndian.Uint64(payload[:8])),
		ModTimeUnixNano: int64(binary.BigEndian.Uint64(payload[8:16])),
	}
	if response.Size < 0 {
		return storageOpenResponse{}, errStorageProtocol
	}
	return response, nil
}

func marshalStorageReadRequest(request storageReadRequest) ([]byte, error) {
	if request.Offset < 0 || request.Length == 0 || request.Length > storageWorkerMaxReadBytes {
		return nil, errStorageProtocol
	}
	payload := make([]byte, 12)
	binary.BigEndian.PutUint64(payload[:8], uint64(request.Offset))
	binary.BigEndian.PutUint32(payload[8:12], request.Length)
	return payload, nil
}

func parseStorageReadRequest(payload []byte) (storageReadRequest, error) {
	if len(payload) != 12 {
		return storageReadRequest{}, errStorageProtocol
	}
	request := storageReadRequest{
		Offset: int64(binary.BigEndian.Uint64(payload[:8])),
		Length: binary.BigEndian.Uint32(payload[8:12]),
	}
	if request.Offset < 0 || request.Length == 0 || request.Length > storageWorkerMaxReadBytes {
		return storageReadRequest{}, errStorageProtocol
	}
	return request, nil
}
