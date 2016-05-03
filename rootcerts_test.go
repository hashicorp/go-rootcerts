package rootcerts

import "testing"

func TestConfigureTLSHandlesNil(t *testing.T) {
	err := ConfigureTLS(nil, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestLoadCACertsHandlesNil(t *testing.T) {
	_, err := LoadCACerts(nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
}
