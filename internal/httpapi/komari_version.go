package httpapi

import (
	"golang.org/x/mod/semver"
	"strings"
)

// Integrated builds retain the fixed upstream API baseline in their version.
func compatibleKomariVersion(version string) bool {
	if version == "1.2.5-fix2" {
		return true
	}
	const prefix = "1.2.5-fix2-aswired."
	if !strings.HasPrefix(version, prefix) {
		return false
	}
	release := "v" + strings.TrimPrefix(version, prefix)
	return semver.IsValid(release) && semver.Canonical(release) == release
}
