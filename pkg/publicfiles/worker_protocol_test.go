package publicfiles

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStorageWorkerFrameRoundTrip(t *testing.T) {
	t.Parallel()

	input := storageWorkerFrame{
		opcode:    storageWorkerListResponse,
		requestID: 42,
		status:    storageWorkerStatusOK,
		flags:     storageWorkerFlagMore,
		payload:   []byte(`{"entry":"report.pdf"}`),
	}
	packet, err := marshalStorageWorkerFrame(input)
	if err != nil {
		t.Fatalf("marshalStorageWorkerFrame() error = %v", err)
	}
	output, err := parseStorageWorkerFrame(packet)
	if err != nil {
		t.Fatalf("parseStorageWorkerFrame() error = %v", err)
	}
	if output.opcode != input.opcode ||
		output.requestID != input.requestID ||
		output.status != input.status ||
		output.flags != input.flags ||
		!bytes.Equal(output.payload, input.payload) {
		t.Fatalf("frame round trip = %#v, want %#v", output, input)
	}

	packet[storageWorkerHeaderBytes] ^= 0xff
	if bytes.Equal(output.payload, packet[storageWorkerHeaderBytes:]) {
		t.Fatal("parsed payload aliases the receive packet")
	}
}

func TestStorageWorkerFrameRejectsMalformedHeaders(t *testing.T) {
	t.Parallel()

	valid, err := marshalStorageWorkerFrame(storageWorkerFrame{
		opcode:    storageWorkerOpenRequest,
		requestID: 7,
		status:    storageWorkerStatusOK,
		payload:   []byte(`{"path":"report.pdf"}`),
	})
	if err != nil {
		t.Fatalf("marshalStorageWorkerFrame() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "truncated header",
			mutate: func(packet []byte) []byte {
				return packet[:storageWorkerHeaderBytes-1]
			},
		},
		{
			name: "wrong magic",
			mutate: func(packet []byte) []byte {
				packet[0] ^= 0xff
				return packet
			},
		},
		{
			name: "wrong version",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint16(packet[4:6], storageWorkerProtocolVersion+1)
				return packet
			},
		},
		{
			name: "unknown opcode",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint16(packet[6:8], uint16(storageWorkerCloseResponse+1))
				return packet
			},
		},
		{
			name: "zero request ID",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint64(packet[8:16], 0)
				return packet
			},
		},
		{
			name: "unknown status",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint16(packet[16:18], uint16(storageWorkerStatusUnsupported+1))
				return packet
			},
		},
		{
			name: "unknown flags",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint16(packet[18:20], storageWorkerFlagMore<<1)
				return packet
			},
		},
		{
			name: "payload length mismatch",
			mutate: func(packet []byte) []byte {
				binary.BigEndian.PutUint32(packet[20:24], uint32(len(packet)))
				return packet
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			packet := test.mutate(append([]byte(nil), valid...))
			if _, err := parseStorageWorkerFrame(packet); !errors.Is(err, errStorageProtocol) {
				t.Fatalf("parseStorageWorkerFrame() error = %v, want errStorageProtocol", err)
			}
		})
	}
}

func TestMarshalStorageWorkerFrameEnforcesBounds(t *testing.T) {
	t.Parallel()

	tests := []storageWorkerFrame{
		{opcode: storageWorkerBootstrapRequest, requestID: 0},
		{opcode: storageWorkerCloseResponse + 1, requestID: 1},
		{opcode: storageWorkerBootstrapRequest, requestID: 1, status: storageWorkerStatusUnsupported + 1},
		{opcode: storageWorkerBootstrapRequest, requestID: 1, flags: storageWorkerFlagMore << 1},
		{
			opcode:    storageWorkerBootstrapRequest,
			requestID: 1,
			payload:   make([]byte, storageWorkerMaxFramePayload+1),
		},
	}
	for index, frame := range tests {
		if _, err := marshalStorageWorkerFrame(frame); !errors.Is(err, errStorageProtocol) {
			t.Fatalf("test %d: marshalStorageWorkerFrame() error = %v, want errStorageProtocol", index, err)
		}
	}
}

func TestStorageWorkerJSONRejectsUnknownAndTrailingFields(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{
		[]byte(`{"path":"report.pdf","mount_id":1,"filesystem_type":1,"extra":true}`),
		[]byte(`{"path":"report.pdf","mount_id":1,"filesystem_type":1} {}`),
		nil,
	} {
		var request storageOpenRequest
		if err := unmarshalStorageWorkerJSON(payload, &request); !errors.Is(err, errStorageProtocol) {
			t.Fatalf("unmarshalStorageWorkerJSON(%q) error = %v, want errStorageProtocol", payload, err)
		}
	}
}

func TestStorageWorkerEntriesRejectUnaddressableNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		`windows\name.txt`,
		".hidden",
		"nested/name.txt",
	} {
		payload, err := json.Marshal([]Entry{{Name: name, Type: "file", Size: 1}})
		if err != nil {
			t.Fatalf("json.Marshal(%q) error = %v", name, err)
		}
		if _, err := decodeStorageWorkerEntries(payload, 1); !errors.Is(err, errStorageProtocol) {
			t.Fatalf("decodeStorageWorkerEntries(%q) error = %v, want errStorageProtocol", name, err)
		}
	}
}

func TestStorageWorkerBinaryMetadataValidation(t *testing.T) {
	t.Parallel()

	if _, err := parseStorageBootstrapResponse(make([]byte, 44)); !errors.Is(err, errStorageProtocol) {
		t.Fatalf("zero mount ID error = %v, want errStorageProtocol", err)
	}
	if _, err := parseStorageOpenResponse(make([]byte, 15)); !errors.Is(err, errStorageProtocol) {
		t.Fatalf("short open response error = %v, want errStorageProtocol", err)
	}
	negativeSize := make([]byte, 16)
	binary.BigEndian.PutUint64(negativeSize[:8], ^uint64(0))
	if _, err := parseStorageOpenResponse(negativeSize); !errors.Is(err, errStorageProtocol) {
		t.Fatalf("negative file size error = %v, want errStorageProtocol", err)
	}
	for _, request := range []storageReadRequest{
		{Offset: -1, Length: 1},
		{Offset: 0, Length: 0},
		{Offset: 0, Length: storageWorkerMaxReadBytes + 1},
	} {
		if _, err := marshalStorageReadRequest(request); !errors.Is(err, errStorageProtocol) {
			t.Fatalf("marshalStorageReadRequest(%+v) error = %v, want errStorageProtocol", request, err)
		}
	}
}

func TestStorageWorkerListBoundFitsWorstCaseLegalNames(t *testing.T) {
	t.Parallel()

	entries := make([]Entry, DefaultMaxDirectoryEntries)
	for index := range entries {
		entries[index] = Entry{
			Name: fmt.Sprintf(
				"%s%04d",
				strings.Repeat("&", 251),
				index,
			),
			Type: "file",
			Size: int64(index),
		}
	}
	payload, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if len(payload) <= 512<<10 {
		t.Fatalf("worst-case fixture size = %d, want proof it exceeds the retired 512 KiB bound", len(payload))
	}
	if len(payload) > storageWorkerMaxListPayload {
		t.Fatalf("worst-case fixture size = %d, exceeds reviewed bound %d", len(payload), storageWorkerMaxListPayload)
	}
	decoded, err := decodeStorageWorkerEntries(payload, DefaultMaxDirectoryEntries)
	if err != nil {
		t.Fatalf("decodeStorageWorkerEntries() error = %v", err)
	}
	if len(decoded) != len(entries) {
		t.Fatalf("decoded entries = %d, want %d", len(decoded), len(entries))
	}
}
