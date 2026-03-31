package utils

// IsValidIATACode validates whether a code is a valid IATA airport code
// For now, this is a placeholder that accepts 3-letter codes
// In production, you would validate against a database of known IATA codes
func IsValidIATACode(code string) bool {
	if len(code) != 3 {
		return false
	}

	// Check if all characters are uppercase letters
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return false
		}
	}

	// TODO: Validate against known IATA codes
	// This could be:
	// 1. A hardcoded set for common codes
	// 2. A loaded CSV/JSON file
	// 3. An external API call (with caching)

	return true
}
