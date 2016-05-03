package rootcerts

import "testing"

func TestSystemCAsOnDarwin(t *testing.T) {
	pool, err := LoadSystemCAs()
	if err != nil {
		t.Fatalf("Got error: %s", err)
	}
}
