//nolint:gochecknoinits // Intentional init function to load claims from environment
package server

import (
	"encoding/json"
	"fmt"
	"os"
)

// Example usage:
// export DEX_CUSTOM_CLAIMS_STATIC='{"policy": {"pgrole": "authn"}, "anotherclaim": "value"}'
var customClaims map[string]any

func init() {
	if claimsStr := os.Getenv("DEX_CUSTOM_CLAIMS_STATIC"); claimsStr != "" {
		if err := json.Unmarshal([]byte(claimsStr), &customClaims); err != nil {
			fmt.Printf("error parsing custom claims JSON: %v\n", err)
		} else {
			fmt.Println("custom claims loaded:", customClaims)
		}
	}
}

// MarshalJSON includes dynamic custom claims alongside standard claims
func (c idTokenClaims) MarshalJSON() ([]byte, error) {
	type defaultClaims idTokenClaims
	dc := defaultClaims(c)

	// Convert to map for manipulation
	b, err := json.Marshal(dc)
	if err != nil {
		return nil, err
	}

	allClaims := make(map[string]any)
	if err := json.Unmarshal(b, &allClaims); err != nil {
		return nil, err
	}

	// Add custom claims, skipping any that would override standard claims
	for k, v := range c.CustomClaims {
		if _, exists := allClaims[k]; !exists {
			allClaims[k] = v
		}
	}

	return json.Marshal(allClaims)
}
