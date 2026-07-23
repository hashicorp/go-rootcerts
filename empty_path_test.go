package rootcerts

import "testing"

func TestLoadCAFileEmptyPath(t *testing.T) {
	if _, err := LoadCAFile("  "); err == nil {
		t.Fatal("expected error")
	}
	if _, err := LoadCAPath(""); err == nil {
		t.Fatal("expected error")
	}
}
