package vendors

import "encoding/xml"

type SearchJobXMLResponse struct {
	XMLName xml.Name `xml:"response"`
	Sid     string   `xml:"sid"`
}

type SearchJobResponse struct {
	Sid string `json:"sid"`
}

type JobStatusResponse struct {
	Entry []struct {
		Content struct {
			IsDone bool `json:"isDone"`
		} `json:"content"`
	} `json:"entry"`
}
type SearchResultsResponse struct {
	Entry []struct {
		Content struct {
			Results []map[string]interface{} `json:"results"`
		} `json:"content"`
	} `json:"entry"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

type SearchResultsEntry struct {
	Results []map[string]interface{} `json:"results"`
	Links   struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (s *SearchResultsResponse) GetNext() string {
	if len(s.Entry) > 0 {
		return s.Entry[0].Content.Results[0]["next"].(string)
	}
	return ""
}

func (s *SearchResultsResponse) GetResults() []map[string]interface{} {
	if len(s.Entry) > 0 {
		return s.Entry[0].Content.Results
	}
	return nil
}

func (s *SearchResultsEntry) GetNext() string {
	if len(s.Links.Next) > 0 {
		return s.Links.Next
	}
	return ""
}

func (s *SearchResultsEntry) GetResults() []map[string]interface{} {
	if len(s.Results) > 0 {
		return s.Results
	}
	return nil
}
