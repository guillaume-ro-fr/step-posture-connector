package shared

import "testing"

func TestExtractSCEPSerial(t *testing.T) {
	cases := []struct {
		name         string
		serialNumber string
		commonName   string
		want         string
		wantErr      bool
	}{
		{name: "prefers serialNumber attribute", serialNumber: "C02ABCDEFGH1", commonName: "some-other-cn", want: "C02ABCDEFGH1"},
		{name: "falls back to commonName", serialNumber: "", commonName: "C02ABCDEFGH1", want: "C02ABCDEFGH1"},
		{name: "both empty is an error", serialNumber: "", commonName: "", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExtractSCEPSerial(c.serialNumber, c.commonName)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got serial %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestValidateSerial(t *testing.T) {
	cases := []struct {
		name    string
		serial  string
		wantErr bool
	}{
		{name: "valid serial", serial: "C02ABCDEFGH1"},
		{name: "too short", serial: "SHORT1", wantErr: true},
		{name: "too long", serial: "THISISWAYTOOLONG12345", wantErr: true},
		{name: "empty", serial: "", wantErr: true},
		{name: "non-alphanumeric", serial: "C02-ABCDEF1", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateSerial(c.serial)
			if c.wantErr && err == nil {
				t.Fatalf("expected an error for serial %q", c.serial)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error for serial %q: %s", c.serial, err)
			}
		})
	}
}

func TestCompareChallenge(t *testing.T) {
	if !CompareChallenge("s3cr3t", "s3cr3t") {
		t.Fatal("expected matching challenges to compare equal")
	}
	if CompareChallenge("s3cr3t", "other") {
		t.Fatal("expected mismatched challenges to compare unequal")
	}
	if CompareChallenge("", "") {
		t.Fatal("expected two empty challenges to never compare equal")
	}
	if CompareChallenge("s3cr3t", "") || CompareChallenge("", "s3cr3t") {
		t.Fatal("expected an empty presented or expected challenge to never compare equal")
	}
}
