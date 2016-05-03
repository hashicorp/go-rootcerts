package rootcerts

import "testing"

func TestSystemCAsOnDarwin(t *testing.T) {
	_, err := LoadSystemCAs()
	if err != nil {
		t.Fatalf("Got error: %s", err)
	}
}
