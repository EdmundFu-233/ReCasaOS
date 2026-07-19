package file

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// ReadOSRelease parses the first available freedesktop.org os-release file.
func ReadOSRelease() (map[string]string, error) {
	var failures []error
	for _, filename := range osReleasePaths {
		values, err := readOSRelease(filename)
		if err == nil {
			return values, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", filename, err))
	}
	return nil, errors.Join(failures...)
}

func readOSRelease(filename string) (map[string]string, error) {
	input, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer input.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if len(value) >= 2 && value[0] == '"' {
			if unquoted, quoteErr := strconv.Unquote(value); quoteErr == nil {
				value = unquoted
			}
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
