package vendors

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
