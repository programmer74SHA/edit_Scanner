package domain

import "strings"

// MultiValueFieldUtils provides utilities for managing multi-value fields (comma-separated)

// UpdateMultiValueField adds a new value to a multi-value field if it doesn't already exist
// Returns the updated field value
func UpdateMultiValueField(currentValue, newValue string) string {
	if currentValue == "" {
		return newValue
	}

	newValue = strings.TrimSpace(newValue)

	if newValue == "" {
		return currentValue
	}

	values := strings.Split(currentValue, ", ")
	for _, value := range values {
		if strings.TrimSpace(value) == newValue {
			return currentValue // Already exists, no change needed
		}
	}

	// Add new value
	return currentValue + ", " + newValue
}

// RemoveFromMultiValueField removes a value from a multi-value field
// Returns the updated field value
func RemoveFromMultiValueField(currentValue, valueToRemove string) string {
	if currentValue == "" {
		return ""
	}

	valueToRemove = strings.TrimSpace(valueToRemove)
	if valueToRemove == "" {
		return currentValue
	}

	values := strings.Split(currentValue, ", ")
	var filteredValues []string

	for _, value := range values {
		if strings.TrimSpace(value) != valueToRemove {
			filteredValues = append(filteredValues, strings.TrimSpace(value))
		}
	}

	return strings.Join(filteredValues, ", ")
}

// SplitMultiValueField splits a multi-value field into individual values
func SplitMultiValueField(fieldValue string) []string {
	if fieldValue == "" {
		return []string{}
	}

	values := strings.Split(fieldValue, ", ")
	var trimmedValues []string

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			trimmedValues = append(trimmedValues, trimmed)
		}
	}

	return trimmedValues
}

// ContainsValue checks if a multi-value field contains a specific value
func ContainsValue(fieldValue, searchValue string) bool {
	if fieldValue == "" || searchValue == "" {
		return false
	}

	values := SplitMultiValueField(fieldValue)
	searchValue = strings.TrimSpace(searchValue)

	for _, value := range values {
		if value == searchValue {
			return true
		}
	}

	return false
}

// ValidateMultiValueField validates that all values in a multi-value field are from allowed values
func ValidateMultiValueField(fieldValue string, allowedValues []string) bool {
	if fieldValue == "" {
		return true // Empty field is valid
	}

	values := SplitMultiValueField(fieldValue)

	for _, value := range values {
		found := false
		for _, allowed := range allowedValues {
			if value == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// NormalizeMultiValueField normalizes values in a multi-value field using a normalization function
// and ensures all values are unique
func NormalizeMultiValueField(fieldValue string, normalizeFunc func(string) string) string {
	if fieldValue == "" {
		return ""
	}

	values := SplitMultiValueField(fieldValue)
	var normalizedValues []string
	seen := make(map[string]bool)

	for _, value := range values {
		normalized := normalizeFunc(value)
		if normalized != "" && !seen[normalized] {
			normalizedValues = append(normalizedValues, normalized)
			seen[normalized] = true
		}
	}

	return strings.Join(normalizedValues, ", ")
}
