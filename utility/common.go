package utility

func Contains[K comparable](s []K, str K) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
func RemoveDuplicateInt(intSlice []int) []int {
	allKeys := make(map[int]bool)
	list := []int{}
	for _, item := range intSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
func RemoveDuplicateString(stringSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range stringSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
