package helpers

// Found is a generic function that checkks if value is in arr. If it is present, it returns the index and true else
// it returns -1 and false
func Found[T comparable](arr []T, value T) (int, bool) {
	for index, v := range arr {
		if v == value {
			return index, true
		}
	}

	return -1, false
}
