package httpapi

import "testing"

func TestIntegratedKomariVersionCompatibility(t *testing.T) {
	for _, v := range []string{"1.2.5-fix2", "1.2.5-fix2-aswired.1.0.0", "1.2.5-fix2-aswired.1.1.0-rc.1"} {
		if !compatibleKomariVersion(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"1.2.5", "1.3.0", "1.2.5-fix2-unknown", "1.2.5-fix2-aswired.", "1.2.5-fix2-aswired.1"} {
		if compatibleKomariVersion(v) {
			t.Fatal(v)
		}
	}
}
