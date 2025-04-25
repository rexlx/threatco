package vendors

import (
	"fmt"
	"strings"
)

const ()

type CSFalconIOCResponse struct {
	Resources []map[string]interface{} `json:"resources"` //  Use map[string]interface{} initially, then create a struct
	Errors    []struct {
		ID      string `json:"id"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Meta struct {
		QueryTime float64 `json:"query_time"`
		// Add other metadata fields as needed
	} `json:"meta"`
}

type CSIndicatorRequest struct {
	Filter string `json:"filter"`
	Sort   []struct {
		Field string `json:"field"`
		Order string `json:"order"`
	} `json:"sort"`
}

func CSFalconFilterBuilder(_type, value string, args ...string) string {
	// Initialize the filter parts with required type and value
	filters := []string{
		fmt.Sprintf("type:'%s'", _type),
		fmt.Sprintf("value:'%s'", value),
	}

	// Process optional arguments (must be in key-value pairs)
	if len(args)%2 != 0 {
		// If args length is odd, ignore the last incomplete pair
		args = args[:len(args)-1]
	}

	for i := 0; i < len(args); i += 2 {
		key := args[i]
		val := args[i+1]
		filters = append(filters, fmt.Sprintf("%s:'%s'", key, val))
	}

	// Join filters with '+' (AND operator)
	return strings.Join(filters, "+")
}
