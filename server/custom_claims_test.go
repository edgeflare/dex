package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"testing"
	"text/template"

	"github.com/dexidp/dex/storage"
)

// discardLogger returns a *slog.Logger that silently discards all output,
// keeping test output clean while still exercising logging code paths.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubEnricher is a [ClaimsEnricher] that either injects a fixed set of
// claims or returns a pre-configured error.
type stubEnricher struct {
	claims map[string]any
	err    error
}

func (s *stubEnricher) Enrich(_ context.Context, claims *storage.Claims) error {
	if s.err != nil {
		return s.err
	}
	if claims.CustomClaims == nil {
		claims.CustomClaims = make(map[string]any)
	}
	maps.Copy(claims.CustomClaims, s.claims)
	return nil
}

// newEnricherNoConn creates a [ClaimsEnricherPostgres] with a nil DB, useful
// for testing methods that don't touch the database (e.g. renderArgs).
func newEnricherNoConn(t *testing.T, query, argsTmplJSON string) *ClaimsEnricherPostgres {
	t.Helper()
	var argTmplStrs []string
	if argsTmplJSON != "" {
		if err := json.Unmarshal([]byte(argsTmplJSON), &argTmplStrs); err != nil {
			t.Fatalf("newEnricherNoConn: parsing args JSON: %v", err)
		}
	}
	argTemplates := make([]*template.Template, len(argTmplStrs))
	for i, s := range argTmplStrs {
		tmpl, err := template.New(fmt.Sprintf("arg%d", i)).Parse(s)
		if err != nil {
			t.Fatalf("newEnricherNoConn: parsing template [%d] %q: %v", i, s, err)
		}
		argTemplates[i] = tmpl
	}
	return &ClaimsEnricherPostgres{
		db:           nil,
		query:        query,
		argTemplates: argTemplates,
		logger:       discardLogger(),
	}
}

// mustMarshalUnmarshal round-trips tok through MarshalJSON and json.Unmarshal,
// returning the resulting map. Fails the test on any error.
func mustMarshalUnmarshal(t *testing.T, tok idTokenClaims) map[string]any {
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

func TestStripReserved(t *testing.T) {
	tests := []struct {
		name        string
		input       map[string]any
		wantRemoved int
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name:        "no reserved keys",
			input:       map[string]any{"role": "admin", "org": "acme"},
			wantRemoved: 0,
			wantPresent: []string{"role", "org"},
		},
		{
			name:        "all reserved",
			input:       map[string]any{"iss": "x", "sub": "y", "aud": "z"},
			wantRemoved: 3,
			wantAbsent:  []string{"iss", "sub", "aud"},
		},
		{
			name:        "mixed",
			input:       map[string]any{"role": "admin", "email": "x@y.com", "org": "acme"},
			wantRemoved: 1,
			wantPresent: []string{"role", "org"},
			wantAbsent:  []string{"email"},
		},
		{
			name:        "empty map",
			input:       map[string]any{},
			wantRemoved: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := stripReserved(tc.input)
			if n != tc.wantRemoved {
				t.Errorf("removed %d, want %d", n, tc.wantRemoved)
			}
			for _, k := range tc.wantPresent {
				if _, ok := tc.input[k]; !ok {
					t.Errorf("key %q should remain but was removed", k)
				}
			}
			for _, k := range tc.wantAbsent {
				if _, ok := tc.input[k]; ok {
					t.Errorf("key %q should be removed but remains", k)
				}
			}
		})
	}
}

func TestNormalizeDBValue(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		wantJSON string
	}{
		{"string passthrough", "hello", `"hello"`},
		{"int64 passthrough", int64(42), `42`},
		{"bytes valid JSON object", []byte(`{"a":1}`), `{"a":1}`},
		{"bytes valid JSON array", []byte(`[1,2,3]`), `[1,2,3]`},
		{"bytes not JSON falls back to string", []byte("plain text"), `"plain text"`},
		{"nil passthrough", nil, `null`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeDBValue(tc.input)
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(b) != tc.wantJSON {
				t.Errorf("got %s, want %s", b, tc.wantJSON)
			}
		})
	}
}

func TestClaimsEnricherStatic_Enrich(t *testing.T) {
	logger := discardLogger()
	ctx := context.Background()

	t.Run("injects claims into empty CustomClaims", func(t *testing.T) {
		e := NewClaimsEnricherStatic(map[string]any{"env": "prod", "region": "eu"}, logger)
		claims := &storage.Claims{}
		if err := e.Enrich(ctx, claims); err != nil {
			t.Fatal(err)
		}
		if claims.CustomClaims["env"] != "prod" {
			t.Errorf("env = %v, want prod", claims.CustomClaims["env"])
		}
		if claims.CustomClaims["region"] != "eu" {
			t.Errorf("region = %v, want eu", claims.CustomClaims["region"])
		}
	})

	t.Run("existing keys take precedence over static", func(t *testing.T) {
		e := NewClaimsEnricherStatic(map[string]any{"role": "viewer"}, logger)
		claims := &storage.Claims{CustomClaims: map[string]any{"role": "admin"}}
		if err := e.Enrich(ctx, claims); err != nil {
			t.Fatal(err)
		}
		if claims.CustomClaims["role"] != "admin" {
			t.Errorf("role = %v, want admin (existing should win)", claims.CustomClaims["role"])
		}
	})

	t.Run("reserved claims are stripped at construction", func(t *testing.T) {
		e := NewClaimsEnricherStatic(map[string]any{"role": "admin", "iss": "evil", "sub": "hacked"}, logger)
		claims := &storage.Claims{}
		_ = e.Enrich(ctx, claims)
		for _, reserved := range []string{"iss", "sub"} {
			if _, ok := claims.CustomClaims[reserved]; ok {
				t.Errorf("reserved claim %q should have been stripped", reserved)
			}
		}
		if claims.CustomClaims["role"] != "admin" {
			t.Error("non-reserved claim 'role' should remain")
		}
	})

	t.Run("no-op when claims map is empty", func(t *testing.T) {
		e := NewClaimsEnricherStatic(map[string]any{}, logger)
		claims := &storage.Claims{}
		_ = e.Enrich(ctx, claims)
		if claims.CustomClaims != nil {
			t.Error("CustomClaims should remain nil when enricher has no claims")
		}
	})
}

func TestClaimsEnricherChain(t *testing.T) {
	ctx := context.Background()

	t.Run("runs enrichers in order and later wins on conflict", func(t *testing.T) {
		a := &stubEnricher{claims: map[string]any{"role": "viewer", "org": "acme"}}
		b := &stubEnricher{claims: map[string]any{"role": "admin"}}
		chain := NewClaimsEnricherChain(a, b)
		claims := &storage.Claims{}
		if err := chain.Enrich(ctx, claims); err != nil {
			t.Fatal(err)
		}
		if claims.CustomClaims["role"] != "admin" {
			t.Errorf("role = %v, want admin (b should win)", claims.CustomClaims["role"])
		}
		if claims.CustomClaims["org"] != "acme" {
			t.Errorf("org = %v, want acme (only set by a)", claims.CustomClaims["org"])
		}
	})

	t.Run("nil enrichers are skipped", func(t *testing.T) {
		chain := NewClaimsEnricherChain(nil, &stubEnricher{claims: map[string]any{"x": "1"}}, nil)
		claims := &storage.Claims{}
		if err := chain.Enrich(ctx, claims); err != nil {
			t.Fatal(err)
		}
		if claims.CustomClaims["x"] != "1" {
			t.Errorf("x = %v, want 1", claims.CustomClaims["x"])
		}
	})

	t.Run("first error aborts chain", func(t *testing.T) {
		sentinel := errors.New("enricher boom")
		a := &stubEnricher{err: sentinel}
		b := &stubEnricher{claims: map[string]any{"should_not": "appear"}}
		chain := NewClaimsEnricherChain(a, b)
		claims := &storage.Claims{}
		if err := chain.Enrich(ctx, claims); !errors.Is(err, sentinel) {
			t.Errorf("expected sentinel error, got %v", err)
		}
		if claims.CustomClaims["should_not"] != nil {
			t.Error("second enricher must not run after first fails")
		}
	})

	t.Run("empty chain is a no-op", func(t *testing.T) {
		chain := NewClaimsEnricherChain()
		claims := &storage.Claims{}
		if err := chain.Enrich(ctx, claims); err != nil {
			t.Fatal(err)
		}
		if claims.CustomClaims != nil {
			t.Error("expected nil CustomClaims from empty chain")
		}
	})
}

func TestNewClaimsTemplateData(t *testing.T) {
	c := &storage.Claims{
		UserID:            "uid-1",
		Email:             "user@example.com",
		Username:          "user",
		PreferredUsername: "User Name",
		Groups:            []string{"admins"}, // intentionally absent from template data
	}
	data := newClaimsTemplateData(c)

	if data.UserID != c.UserID {
		t.Errorf("UserID = %q, want %q", data.UserID, c.UserID)
	}
	if data.Email != c.Email {
		t.Errorf("Email = %q, want %q", data.Email, c.Email)
	}
	if data.Username != c.Username {
		t.Errorf("Username = %q, want %q", data.Username, c.Username)
	}
	if data.PreferredUsername != c.PreferredUsername {
		t.Errorf("PreferredUsername = %q, want %q", data.PreferredUsername, c.PreferredUsername)
	}
	// Groups is intentionally absent from claimsTemplateData.
	// Accessing data.Groups would be a compile error — the restriction is
	// enforced by the type system, not at runtime.
}

func TestClaimsEnricherPostgres_renderArgs(t *testing.T) {
	t.Run("renders email and userID", func(t *testing.T) {
		argsJSON, _ := json.Marshal([]string{"{{.Email}}", "{{.UserID}}"})
		e := newEnricherNoConn(t, "SELECT 1", string(argsJSON))
		args, err := e.renderArgs(&storage.Claims{Email: "a@b.com", UserID: "uid-99"})
		if err != nil {
			t.Fatal(err)
		}
		if args[0] != "a@b.com" {
			t.Errorf("arg[0] = %q, want a@b.com", args[0])
		}
		if args[1] != "uid-99" {
			t.Errorf("arg[1] = %q, want uid-99", args[1])
		}
	})

	t.Run("renders username and preferredUsername", func(t *testing.T) {
		argsJSON, _ := json.Marshal([]string{"{{.Username}}", "{{.PreferredUsername}}"})
		e := newEnricherNoConn(t, "SELECT 1", string(argsJSON))
		args, err := e.renderArgs(&storage.Claims{Username: "jdoe", PreferredUsername: "John Doe"})
		if err != nil {
			t.Fatal(err)
		}
		if args[0] != "jdoe" {
			t.Errorf("arg[0] = %q, want jdoe", args[0])
		}
		if args[1] != "John Doe" {
			t.Errorf("arg[1] = %q, want John Doe", args[1])
		}
	})

	t.Run("empty arg list returns empty slice", func(t *testing.T) {
		e := newEnricherNoConn(t, "SELECT 1", "")
		args, err := e.renderArgs(&storage.Claims{Email: "x@y.com"})
		if err != nil {
			t.Fatal(err)
		}
		if len(args) != 0 {
			t.Errorf("expected 0 args, got %d", len(args))
		}
	})

	t.Run("unknown field causes template execution error", func(t *testing.T) {
		// .Groups is not on claimsTemplateData; missingkey=error makes
		// Execute fail rather than silently rendering a zero value.
		tmpl, err := template.New("bad").Option("missingkey=error").Parse("{{.Groups}}")
		if err != nil {
			t.Fatal(err)
		}
		e := &ClaimsEnricherPostgres{
			query:        "SELECT 1",
			argTemplates: []*template.Template{tmpl},
			logger:       discardLogger(),
		}
		if _, err := e.renderArgs(&storage.Claims{Groups: []string{"admins"}}); err == nil {
			t.Error("expected error for unknown field .Groups, got nil")
		}
	})
}

func TestIDTokenClaims_MarshalJSON(t *testing.T) {
	t.Run("custom claims are injected into output", func(t *testing.T) {
		tok := idTokenClaims{
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
		tok := idTokenClaims{
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
		tok := idTokenClaims{Issuer: "https://example.com", Subject: "user-1"}
		out := mustMarshalUnmarshal(t, tok)
		if out["iss"] != "https://example.com" {
			t.Errorf("iss = %v, want https://example.com", out["iss"])
		}
	})

	t.Run("nested custom claim survives round-trip", func(t *testing.T) {
		tok := idTokenClaims{
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
