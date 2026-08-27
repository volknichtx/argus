package correlation

import "testing"

// The String methods are what the view and the tests print. A wrong label would
// mislabel a finding on screen and misreport it in every failure message.
func TestConcernString(t *testing.T) {
	tests := []struct {
		concern Concern
		want    string
	}{
		{concern: ConcernCritical, want: "critical"},
		{concern: ConcernElevated, want: "elevated"},
		{concern: ConcernNormal, want: "normal"},
		{concern: Concern(99), want: "normal"},
	}

	for _, tc := range tests {
		if got := tc.concern.String(); got != tc.want {
			t.Errorf("Concern(%d).String() = %q, want %q", tc.concern, got, tc.want)
		}
	}
}

// Ordering is what the view relies on to put the worst host first, so the
// grades must stay ranked even if new ones are added between them.
func TestConcernIsOrderedBySeverity(t *testing.T) {
	if !(ConcernCritical > ConcernElevated && ConcernElevated > ConcernNormal) {
		t.Errorf("concern levels are not ranked: %d, %d, %d",
			ConcernNormal, ConcernElevated, ConcernCritical)
	}
}

func TestDirectionString(t *testing.T) {
	if got, want := DirectionInbound.String(), "inbound"; got != want {
		t.Errorf("DirectionInbound.String() = %q, want %q", got, want)
	}

	if got, want := DirectionOutbound.String(), "outbound"; got != want {
		t.Errorf("DirectionOutbound.String() = %q, want %q", got, want)
	}
}
