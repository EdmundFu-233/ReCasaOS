package publicfiles

import "testing"

func TestValidateListenAddressRequiresLiteralLoopback(t *testing.T) {
	tests := []struct {
		value     string
		want      string
		wantError bool
	}{
		{value: "127.0.0.1:39777", want: "127.0.0.1:39777"},
		{value: "[::1]:39777", want: "[::1]:39777"},
		{value: "[::ffff:127.0.0.1]:39777", want: "127.0.0.1:39777"},
		{value: "localhost:39777", wantError: true},
		{value: "0.0.0.0:39777", wantError: true},
		{value: "192.0.2.1:39777", wantError: true},
		{value: "127.0.0.1:0", wantError: true},
		{value: "127.0.0.1:039777", wantError: true},
		{value: "127.0.0.1", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := ValidateListenAddress(test.value)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateListenAddress(%q) error = %v, wantError=%v", test.value, err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("ValidateListenAddress(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}
