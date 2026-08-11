package safety

import "testing"

func TestAssess(t *testing.T) {
	tests := []struct {
		method    string
		hasParams bool
		want      Kind
	}{
		{"network/interface/lan/stations", false, Read},
		{"dhcpd/lease/show", true, Read},
		{"system/name", false, Read},
		{"system/name", true, Write},
		{"wireless/bss/set", true, HighRisk},
		{"wireless/bss/clear", true, HighRisk},
		{"network/interface/lan/config", true, HighRisk},
		{"command", true, Blocked},
		{"config/backup", false, Blocked},
		{"config/backup/raw", false, Blocked},
		{"config/reset", false, Blocked},
		{"admin/future", true, Blocked},
		{"command/run", true, Blocked},
		{"COMMAND", true, Blocked},
		{"/config/reset", true, Blocked},
		{"config//reset", true, Blocked},
		{"config/reset/", true, Blocked},
		{"session/info", false, Read},
		{"session/future", true, Blocked},
		{"firmware/future", true, Blocked},
		{"future/method", false, Unknown},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			if got := Assess(test.method, test.hasParams).Kind; got != test.want {
				t.Fatalf("Assess(%q, %v) = %q, want %q", test.method, test.hasParams, got, test.want)
			}
		})
	}
}
