package tokens

import (
	"encoding/json"
	"testing"
)

// mustMarshalUnmarshal round-trips tok through MarshalJSON and json.Unmarshal,
// returning the resulting map. Fails the test on any error.
func mustMarshalUnmarshal(t *testing.T, tok IDTokenClaims) map[string]any {
	t.Helper()
	b, err := tok.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return out
}

func TestIDTokenClaims_MarshalJSON(t *testing.T) {
	t.Run("custom claims are injected into output", func(t *testing.T) {
		tok := IDTokenClaims{
			Issuer:       "https://example.com",
			Subject:      "user-1",
			CustomClaims: map[string]any{"role": "admin", "org_id": float64(42)},
		}
		out := mustMarshalUnmarshal(t, tok)
		if out["role"] != "admin" {
			t.Errorf("role = %v, want admin", out["role"])
		}
		if out["org_id"] != float64(42) {
			t.Errorf("org_id = %v, want 42", out["org_id"])
		}
	})

	t.Run("custom claims cannot overwrite standard fields", func(t *testing.T) {
		tok := IDTokenClaims{
			Issuer:       "https://example.com",
			Subject:      "user-1",
			CustomClaims: map[string]any{"iss": "evil.example.com", "sub": "hacked"},
		}
		out := mustMarshalUnmarshal(t, tok)
		if out["iss"] != "https://example.com" {
			t.Errorf("iss = %v, standard field should be protected", out["iss"])
		}
		if out["sub"] != "user-1" {
			t.Errorf("sub = %v, standard field should be protected", out["sub"])
		}
	})

	t.Run("nil CustomClaims produces valid JSON", func(t *testing.T) {
		tok := IDTokenClaims{Issuer: "https://example.com", Subject: "user-1"}
		out := mustMarshalUnmarshal(t, tok)
		if out["iss"] != "https://example.com" {
			t.Errorf("iss = %v, want https://example.com", out["iss"])
		}
	})

	t.Run("nested custom claim survives round-trip", func(t *testing.T) {
		tok := IDTokenClaims{
			Issuer:       "https://example.com",
			Subject:      "user-1",
			CustomClaims: map[string]any{"meta": map[string]any{"tier": "gold"}},
		}
		out := mustMarshalUnmarshal(t, tok)
		meta, ok := out["meta"].(map[string]any)
		if !ok {
			t.Fatalf("meta is %T, want map[string]any", out["meta"])
		}
		if meta["tier"] != "gold" {
			t.Errorf("meta.tier = %v, want gold", meta["tier"])
		}
	})
}
