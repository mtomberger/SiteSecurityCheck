package utility

func Contains[K comparable](s []K, str K) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
