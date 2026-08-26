package vendors

import (
	"encoding/json"
)

type CirclCVE5Record struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CveMetadata struct {
		CveID         string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			ProblemTypes []struct {
				Descriptions []struct {
					Lang        string `json:"lang"`
					Description string `json:"description"`
					CweID       string `json:"cweId"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
		} `json:"cna"`
		ADP []struct {
			Title      string `json:"title"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
			ProblemTypes []struct {
				Descriptions []struct {
					Type        string `json:"type"`
					CweID       string `json:"cweId"`
					Description string `json:"description"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Metrics []struct {
				Other struct {
					Type    string          `json:"type"`
					Content json.RawMessage `json:"content"`
				} `json:"other"`
			} `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}
