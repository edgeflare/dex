package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"text/template"
	"time"

	_ "github.com/lib/pq"

	"github.com/dexidp/dex/storage"
)

var (
	errEmptyQuery   = errors.New("query must not be empty")
	errMissingQuery = errors.New("DEX_CUSTOM_CLAIMS_POSTGRES_URI set but DEX_CUSTOM_CLAIMS_POSTGRES_QUERY is empty")
)

// reservedClaims is the set of JWT/OIDC standard claim names that enrichers
// must not overwrite. These are always set by the token issuer; the full list
// is defined in RFC 7519 §4.1 and the OIDC Core 1.0 specification.
var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "iat": {}, "exp": {},
	"email": {}, "email_verified": {}, "locale": {},
	"name": {}, "preferred_username": {}, "at_hash": {},
}

// stripReserved deletes any keys from m that appear in reservedClaims,
// mutating m in place, and returns the number of keys removed.
func stripReserved(m map[string]any) int {
	var n int
	for k := range m {
		if _, ok := reservedClaims[k]; ok {
			delete(m, k)
			n++
		}
	}
	return n
}

// ClaimsEnricher is implemented by types that add custom claims to an ID
// token. Enrich is called once per token issuance and must write its claims
// into claims.CustomClaims. Implementations must not set reserved JWT/OIDC
// claim names (iss, sub, aud, iat, exp, email, …); [stripReserved] is applied
// automatically by each built-in enricher.
type ClaimsEnricher interface {
	Enrich(ctx context.Context, claims *storage.Claims) error
}

// ClaimsEnricherStatic injects a fixed set of claims into every ID token.
// It is configured via the DEX_CUSTOM_CLAIMS_STATIC environment variable,
// which must contain a JSON object. Static claims are applied first in a
// [ClaimsEnricherChain]; later enrichers may override them for the same key.
type ClaimsEnricherStatic struct {
	claims map[string]any
	logger *slog.Logger
}

// NewClaimsEnricherStatic returns a [ClaimsEnricherStatic] that injects
// claims into every token. Reserved claim names are removed from claims
// before the enricher is constructed.
func NewClaimsEnricherStatic(claims map[string]any, logger *slog.Logger) *ClaimsEnricherStatic {
	safe := maps.Clone(claims)
	if n := stripReserved(safe); n > 0 {
		logger.Warn("static claims enricher: dropped reserved claims", "count", n)
	}
	return &ClaimsEnricherStatic{claims: safe, logger: logger}
}

// NewClaimsEnricherStaticFromEnv reads DEX_CUSTOM_CLAIMS_STATIC and returns a
// ready [ClaimsEnricherStatic], or nil if the variable is unset.
func NewClaimsEnricherStaticFromEnv(logger *slog.Logger) (*ClaimsEnricherStatic, error) {
	raw := os.Getenv("DEX_CUSTOM_CLAIMS_STATIC")
	if raw == "" {
		return nil, nil
	}

	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return nil, fmt.Errorf("parsing DEX_CUSTOM_CLAIMS_STATIC: %w", err)
	}

	e := NewClaimsEnricherStatic(claims, logger)
	logger.Info("static claims enricher: loaded claims", "count", len(e.claims))
	return e, nil
}

// Enrich merges the static claims into claims.CustomClaims. Keys already
// present in CustomClaims (written by an earlier enricher) take precedence.
func (e *ClaimsEnricherStatic) Enrich(_ context.Context, claims *storage.Claims) error {
	if len(e.claims) == 0 {
		return nil
	}

	merged := make(map[string]any, len(e.claims)+len(claims.CustomClaims))
	maps.Copy(merged, e.claims)
	maps.Copy(merged, claims.CustomClaims) // existing keys win
	claims.CustomClaims = merged
	return nil
}

// ClaimsEnricherChain runs a sequence of [ClaimsEnricher] implementations in
// registration order. Each enricher's output is merged on top of the previous
// one, so later enrichers take precedence for the same claim key.
type ClaimsEnricherChain struct {
	enrichers []ClaimsEnricher
}

// NewClaimsEnricherChain returns a [ClaimsEnricherChain] that runs each
// provided enricher in sequence. nil entries are silently skipped, so callers
// may pass the return values of NewXxxFromEnv directly without nil-checking.
func NewClaimsEnricherChain(enrichers ...ClaimsEnricher) *ClaimsEnricherChain {
	var filtered []ClaimsEnricher
	for _, e := range enrichers {
		if e != nil {
			filtered = append(filtered, e)
		}
	}
	return &ClaimsEnricherChain{enrichers: filtered}
}

// Enrich runs every enricher in registration order, accumulating results into
// claims.CustomClaims.
func (c *ClaimsEnricherChain) Enrich(ctx context.Context, claims *storage.Claims) error {
	for _, e := range c.enrichers {
		if err := e.Enrich(ctx, claims); err != nil {
			return err
		}
	}
	return nil
}

// claimsTemplateData is the restricted view of [storage.Claims] exposed to
// Go templates in DEX_CUSTOM_CLAIMS_POSTGRES_QUERY_ARGS. Only the fields
// listed here are available; the full Claims struct is intentionally not
// exposed to avoid leaking internal fields into query arguments.
type claimsTemplateData struct {
	UserID            string
	Email             string
	Username          string
	PreferredUsername string
}

func newClaimsTemplateData(c *storage.Claims) claimsTemplateData {
	return claimsTemplateData{
		UserID:            c.UserID,
		Email:             c.Email,
		Username:          c.Username,
		PreferredUsername: c.PreferredUsername,
	}
}

// ClaimsEnricherPostgres fetches custom claims from a PostgreSQL query and
// merges every returned column into the ID token. It is configured through
// three environment variables:
//
//   - DEX_CUSTOM_CLAIMS_POSTGRES_URI — libpq connection URI.
//     See https://www.postgresql.org/docs/current/libpq-connect.html
//
//   - DEX_CUSTOM_CLAIMS_POSTGRES_QUERY — plain SQL with positional
//     placeholders ($1, $2, …). The query must return exactly one row per
//     user; returning more than one row is a configuration error and will
//     cause token issuance to fail. Example:
//
//     SELECT account_id, org_id, role
//     FROM user_claims
//     WHERE email = $1 AND tenant_id = $2
//
//   - DEX_CUSTOM_CLAIMS_POSTGRES_QUERY_ARGS — JSON array of Go template
//     strings rendered against [claimsTemplateData]. Each element becomes one
//     positional argument in order. Available fields: .UserID, .Email,
//     .Username, .PreferredUsername. Example:
//
//     ["{{.Email}}", "{{.UserID}}"]
type ClaimsEnricherPostgres struct {
	db           *sql.DB
	query        string
	argTemplates []*template.Template
	logger       *slog.Logger
}

// NewClaimsEnricherPostgres constructs a [ClaimsEnricherPostgres] from
// explicit values and verifies the connection is reachable via Ping. dsn is a
// libpq connection URI, query is the SQL to execute, and argsTmplJSON is a
// JSON array of Go template strings (may be empty).
func NewClaimsEnricherPostgres(ctx context.Context, dsn, query, argsTmplJSON string, logger *slog.Logger) (*ClaimsEnricherPostgres, error) {
	if query == "" {
		return nil, errEmptyQuery
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	// TODO: make configurable
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging postgres claims DB: %w", err)
	}

	var argTmplStrs []string
	if argsTmplJSON != "" {
		if err := json.Unmarshal([]byte(argsTmplJSON), &argTmplStrs); err != nil {
			db.Close()
			return nil, fmt.Errorf("parsing DEX_CUSTOM_CLAIMS_POSTGRES_QUERY_ARGS: %w", err)
		}
	}

	argTemplates := make([]*template.Template, len(argTmplStrs))
	for i, s := range argTmplStrs {
		t, err := template.New(fmt.Sprintf("arg%d", i)).Parse(s)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("parsing arg template [%d] %q: %w", i, s, err)
		}
		argTemplates[i] = t
	}

	return &ClaimsEnricherPostgres{
		db:           db,
		query:        query,
		argTemplates: argTemplates,
		logger:       logger,
	}, nil
}

// NewClaimsEnricherPostgresFromEnv reads the DEX_CUSTOM_CLAIMS_POSTGRES_*
// environment variables and returns a ready [ClaimsEnricherPostgres]. It
// returns nil without error when DEX_CUSTOM_CLAIMS_POSTGRES_URI is unset.
func NewClaimsEnricherPostgresFromEnv(ctx context.Context, logger *slog.Logger) (*ClaimsEnricherPostgres, error) {
	dsn := os.Getenv("DEX_CUSTOM_CLAIMS_POSTGRES_URI")
	if dsn == "" {
		return nil, nil
	}

	query := os.Getenv("DEX_CUSTOM_CLAIMS_POSTGRES_QUERY")
	if query == "" {
		return nil, errMissingQuery
	}
	return NewClaimsEnricherPostgres(ctx, dsn, query, os.Getenv("DEX_CUSTOM_CLAIMS_POSTGRES_QUERY_ARGS"), logger)
}

// Close releases the underlying database connection pool. It should be called
// when the server shuts down.
func (e *ClaimsEnricherPostgres) Close() error {
	return e.db.Close()
}

// renderArgs evaluates each arg template against a restricted view of claims
// (see [claimsTemplateData]) and returns a []any slice ready to pass directly
// to [sql.DB.QueryContext].
func (e *ClaimsEnricherPostgres) renderArgs(claims *storage.Claims) ([]any, error) {
	data := newClaimsTemplateData(claims)
	args := make([]any, len(e.argTemplates))
	for i, t := range e.argTemplates {
		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("rendering arg template [%d]: %w", i, err)
		}
		args[i] = buf.String()
	}
	return args, nil
}

// Enrich executes the configured query, maps every returned column to a claim,
// strips reserved claim names, and merges the result into claims.CustomClaims.
// When the query returns no rows, Enrich is a no-op. The query must return
// exactly one row; returning more than one row is treated as a configuration
// error and causes token issuance to fail.
func (e *ClaimsEnricherPostgres) Enrich(ctx context.Context, claims *storage.Claims) error {
	args, err := e.renderArgs(claims)
	if err != nil {
		return err
	}

	rows, err := e.db.QueryContext(ctx, e.query, args...)
	if err != nil {
		return fmt.Errorf("executing claims query: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return rows.Err() // nil when simply no rows
	}

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("reading column names: %w", err)
	}

	raw := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return fmt.Errorf("scanning claims row: %w", err)
	}

	// Enforce exactly-one-row contract: the caller is responsible for ensuring
	// their query returns at most one row (e.g. via LIMIT 1 or a unique WHERE
	// clause). A second row is always a misconfiguration.
	if rows.Next() {
		return fmt.Errorf("claims query returned more than one row: ensure the query returns at most one row per user")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating claims rows: %w", err)
	}

	dynamic := make(map[string]any, len(cols))
	for i, col := range cols {
		dynamic[col] = normalizeDBValue(raw[i])
	}

	if n := stripReserved(dynamic); n > 0 {
		e.logger.Warn("postgres claims enricher: dropped reserved claims", "count", n)
	}

	if claims.CustomClaims == nil {
		claims.CustomClaims = dynamic
		return nil
	}
	maps.Copy(claims.CustomClaims, dynamic)
	return nil
}

// normalizeDBValue converts driver-native types into JSON-friendly equivalents.
// []byte values are first attempted as JSON (covering jsonb columns) and fall
// back to a plain string if unmarshalling fails.
func normalizeDBValue(v any) any {
	b, ok := v.([]byte)
	if !ok {
		return v
	}
	var j any
	if err := json.Unmarshal(b, &j); err == nil {
		return j
	}
	return string(b)
}

// NewClaimsEnricherFromEnv reads all DEX_CUSTOM_CLAIMS_* environment variables
// and returns a single [ClaimsEnricher] that runs every configured source in
// order:
//
//  1. Static claims   (DEX_CUSTOM_CLAIMS_STATIC)
//  2. Postgres claims (DEX_CUSTOM_CLAIMS_POSTGRES_*)
//
// Later enrichers take precedence over earlier ones for the same claim key.
// Reserved JWT/OIDC claim names are stripped at each enricher before being
// written to the token. Returns nil without error when no sources are
// configured.
func NewClaimsEnricherFromEnv(ctx context.Context, logger *slog.Logger) (ClaimsEnricher, error) {
	static, err := NewClaimsEnricherStaticFromEnv(logger)
	if err != nil {
		return nil, err
	}

	pg, err := NewClaimsEnricherPostgresFromEnv(ctx, logger)
	if err != nil {
		return nil, err
	}

	// Only append non-nil concrete pointers. A typed nil (*T)(nil) satisfies
	// the ClaimsEnricher interface but would panic on Enrich; passing them
	// directly to NewClaimsEnricherChain bypasses the nil filter there.
	var enrichers []ClaimsEnricher
	if static != nil {
		enrichers = append(enrichers, static)
	}
	if pg != nil {
		enrichers = append(enrichers, pg)
	}

	if len(enrichers) == 0 {
		return nil, nil
	}
	return NewClaimsEnricherChain(enrichers...), nil
}

func (c idTokenClaims) MarshalJSON() ([]byte, error) {
	type defaultClaims idTokenClaims
	b, err := json.Marshal(defaultClaims(c))
	if err != nil {
		return nil, err
	}

	allClaims := make(map[string]any)
	if err := json.Unmarshal(b, &allClaims); err != nil {
		return nil, err
	}

	for k, v := range c.CustomClaims {
		if _, exists := allClaims[k]; !exists {
			allClaims[k] = v
		}
	}
	return json.Marshal(allClaims)
}
