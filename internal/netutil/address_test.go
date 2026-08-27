package netutil

import "testing"

func TestSplitSocketAddressZone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantZone string
	}{
		{
			name:     "plain ipv4",
			input:    "10.0.0.10",
			wantHost: "10.0.0.10",
			wantZone: "",
		},
		{
			name:     "ipv4 with interface suffix",
			input:    "10.0.0.10%eno1",
			wantHost: "10.0.0.10",
			wantZone: "eno1",
		},
		{
			name:     "plain ipv6",
			input:    "2001:db8:2:7c5::",
			wantHost: "2001:db8:2:7c5::",
			wantZone: "",
		},
		{
			name:     "ipv6 with zone",
			input:    "fe80::1234%eno1",
			wantHost: "fe80::1234",
			wantZone: "eno1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, zone := SplitSocketAddressZone(tc.input)

			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}

			if zone != tc.wantZone {
				t.Errorf("zone = %q, want %q", zone, tc.wantZone)
			}
		})
	}
}

func TestParseIPFromSocketAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain ipv4",
			input: "10.0.0.10",
			want:  "10.0.0.10",
		},
		{
			name:  "ipv4 with interface suffix from ss",
			input: "10.0.0.10%eno1",
			want:  "10.0.0.10",
		},
		{
			name:  "plain ipv6",
			input: "2001:db8:2:7c5::",
			want:  "2001:db8:2:7c5::",
		},
		{
			name:  "ipv6 with zone",
			input: "fe80::1234%eno1",
			want:  "fe80::1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseIPFromSocketAddress(tc.input)
			if got == nil {
				t.Fatalf(
					"parseIPFromSocketAddress(%q) = nil",
					tc.input,
				)
			}

			if got.String() != tc.want {
				t.Errorf(
					"parseIPFromSocketAddress(%q) = %q, want %q",
					tc.input,
					got.String(),
					tc.want,
				)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "public ipv4", input: "192.0.2.8", want: true},
		{name: "public ipv4 second range", input: "198.51.100.26", want: true},
		{name: "public ipv6", input: "2001:db8:4::10", want: true},
		{name: "private ipv4 class c", input: "10.0.0.20", want: false},
		{name: "private ipv4 class a", input: "10.1.2.3", want: false},
		{name: "private ipv4 class b", input: "172.16.0.1", want: false},
		{name: "unique local ipv6", input: "fd00::1", want: false},
		{name: "loopback ipv4", input: "127.0.0.1", want: false},
		{name: "loopback ipv6", input: "::1", want: false},
		{name: "unspecified", input: "0.0.0.0", want: false},
		{name: "link local ipv6", input: "fe80::1", want: false},
		{name: "multicast", input: "224.0.0.1", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsPublicIP(ParseIPFromSocketAddress(tc.input))

			if got != tc.want {
				t.Errorf("IsPublicIP(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}

	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}

func TestIsRemoteHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "remote private ip", input: "10.0.0.20", want: true},
		{name: "remote public ip", input: "192.0.2.8", want: true},
		{name: "remote ip with zone", input: "10.0.0.20%eno1", want: true},
		{name: "loopback ipv4", input: "127.0.0.1", want: false},
		{name: "loopback ipv6", input: "::1", want: false},

		// who(1) fills these in for local sessions; none of them is an IP.
		{name: "who local placeholder", input: "local", want: false},
		{name: "x display", input: ":0", want: false},
		{name: "tmux pane", input: "tmux(523831).%0", want: false},
		{name: "resolved hostname", input: "workstation.lan", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRemoteHost(tc.input); got != tc.want {
				t.Errorf("IsRemoteHost(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
