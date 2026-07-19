/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-05-13 18:15:46
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-21 15:27:53
 * @FilePath: /CasaOS/pkg/utils/version/version.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package version

import (
	"strconv"
	"strings"

	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/model"
	"golang.org/x/mod/semver"
)

func IsNeedUpdate(version model.Version) (bool, model.Version) {
	if remoteLegacy, ok := legacyFourPartVersion(version.Version); ok {
		currentCore, currentOK := numericVersionCore(common.VERSION)
		if !currentOK {
			return false, version
		}
		return compareNumericVersion(remoteLegacy, currentCore) > 0, version
	}
	remote := canonicalVersion(version.Version)
	current := canonicalVersion(common.VERSION)
	if remote == "" || current == "" {
		return false, version
	}
	if strings.HasPrefix(semver.Prerelease(remote), "-recasaos.") {
		return semver.Compare(remote, current) > 0, version
	}
	return semver.Compare(remote, forkBaseVersion(current)) > 0, version
}

func legacyFourPartVersion(value string) ([4]uint64, bool) {
	core, ok := numericVersionCore(value)
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "v")
	return core, ok && !strings.ContainsAny(trimmed, "-+") && len(strings.Split(trimmed, ".")) == 4
}

func numericVersionCore(value string) ([4]uint64, bool) {
	var result [4]uint64
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if marker := strings.IndexAny(value, "-+"); marker >= 0 {
		value = value[:marker]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 && len(parts) != 4 {
		return result, false
	}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, false
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return result, false
		}
		result[index] = number
	}
	return result, true
}

func compareNumericVersion(left, right [4]uint64) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func forkBaseVersion(value string) string {
	if marker := strings.Index(value, "-recasaos."); marker >= 0 {
		return value[:marker]
	}
	return value
}

func canonicalVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "v") {
		value = "v" + value
	}
	return semver.Canonical(value)
}
