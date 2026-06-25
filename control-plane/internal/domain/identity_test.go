package domain

import "testing"

func TestIdentityValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      Identity
		wantErr bool
	}{
		{"human ok", Identity{ID: "u1", Type: IdentityHuman}, false},
		{"human with owner is invalid", Identity{ID: "u1", Type: IdentityHuman, Owner: "u2"}, true},
		{"nhi requires owner", Identity{ID: "svc1", Type: IdentityNHI}, true},
		{"nhi with owner ok", Identity{ID: "svc1", Type: IdentityNHI, Owner: "u1"}, false},
		{"unknown type invalid", Identity{ID: "x", Type: "robot"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEntitlementIDs(t *testing.T) {
	i := Identity{Entitlements: []Entitlement{{ID: "a"}, {ID: "b"}}}
	got := i.EntitlementIDs()
	if len(got) != 2 || got["a"].ID != "a" {
		t.Fatalf("EntitlementIDs() = %#v", got)
	}
}
