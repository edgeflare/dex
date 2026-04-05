package tokens

import "encoding/json"

// MarshalJSON merges CustomClaims into the token payload. Custom claims never
// override a standard claim that is already present.
func (c IDTokenClaims) MarshalJSON() ([]byte, error) {
	type defaultClaims IDTokenClaims
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
