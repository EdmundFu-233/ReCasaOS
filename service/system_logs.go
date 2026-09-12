package service

import (
	"bytes"
	"io"
	"os"
)

const (
	defaultCasaOSLogLines = 100
	maxCasaOSLogLines     = 1000
	maxCasaOSLogBytes     = int64(2 << 20)
)

// readCasaOSLogTail keeps the authenticated log endpoint bounded even when
// the on-disk log has grown without rotation. It reads only a fixed-size tail
// and returns complete lines so a large historical prefix is never loaded into
// the service process.
func readCasaOSLogTail(logFile *os.File, requestedLines int) (string, error) {
	lineLimit := requestedLines
	if lineLimit < 1 {
		lineLimit = defaultCasaOSLogLines
	}
	if lineLimit > maxCasaOSLogLines {
		lineLimit = maxCasaOSLogLines
	}

	info, err := logFile.Stat()
	if err != nil {
		return "", err
	}
	start := int64(0)
	if info.Size() > maxCasaOSLogBytes {
		start = info.Size() - maxCasaOSLogBytes
	}
	if _, err := logFile.Seek(start, io.SeekStart); err != nil {
		return "", err
	}

	content, err := io.ReadAll(io.LimitReader(logFile, maxCasaOSLogBytes))
	if err != nil {
		return "", err
	}
	if start > 0 {
		firstLineEnd := bytes.IndexByte(content, '\n')
		if firstLineEnd < 0 {
			return "", nil
		}
		content = content[firstLineEnd+1:]
	}

	return string(lastCasaOSLogLines(content, lineLimit)), nil
}

func lastCasaOSLogLines(content []byte, lineLimit int) []byte {
	if len(content) == 0 || lineLimit < 1 {
		return nil
	}

	end := len(content)
	if content[end-1] == '\n' {
		end--
	}
	start := 0
	lineCount := 0
	for index := end - 1; index >= 0; index-- {
		if content[index] != '\n' {
			continue
		}
		lineCount++
		if lineCount == lineLimit {
			start = index + 1
			break
		}
	}
	return content[start:]
}
