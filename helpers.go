package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
	"github.com/google/uuid"
	"github.com/rexlx/threatco/vendors"
)

func (s *Server) ProxyHelper(req ProxyRequest) ([]byte, error) {
	var resp []byte
	// var err error
	switch req.To {
	case "virustotal":
		return s.VirusTotalHelper(req)
	case "misp":
		return s.MispHelper(req)
	case "deepfry":
		return s.DeepFryHelper(req)
	case "mandiant":
		return s.MandiantHelper(req)
	case "crowdstrike":
		return s.CrowdstrikeHelper(req)
	case "splunk":
		return s.SplunkHelper(req)
	case "domaintools":
		switch req.Route {
		case "domain":
			return s.DomainToolsClassicHelper(req)
		default:
			return s.DomainToolsHelper(req)
		}
	default:
		return resp, fmt.Errorf("bad target")
	}
}

func Sign(username, key, time, uri string) string {
	p := username + time + uri
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(p))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func WhoIsURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	var _type string
	switch req.Type {
	case "domain":
		_type = "domain"
	case "ipv4":
		_type = "ip"
	case "ipv6":
		_type = "ip"
	case "url":
		_type = "url"
	case "email":
		_type = "email"
	default:
		_type = "domain"
	}
	uri := fmt.Sprintf("/v1/%v/?%v=%v&api_username=%v&api_key=%v", req.Route, _type, req.Value, uname, key)
	// sig := Sign(uname, key, time, uri)
	return fmt.Sprintf("%s%s", url, uri)
}

func IrisInvestigateURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	var _type string
	switch req.Type {
	case "domain":
		_type = "domain"
	case "ipv4":
		_type = "ip"
	case "ipv6":
		_type = "ip"
	case "url":
		_type = "url"
	case "email":
		_type = "email"
	default:
		_type = "domain"
	}
	uri := fmt.Sprintf("/v1/%v/?%v=%v&api_username=%v&api_key=%v", req.Route, _type, req.Value, uname, key)
	// sig := Sign(uname, key, time, uri)
	return fmt.Sprintf("%s%s", url, uri)
}

func IrisProfileURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	uri := fmt.Sprintf("/v1/%s/%s", req.Route, req.Value)
	return fmt.Sprintf("%s%s", url, uri)
}

func IrisDetectURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	uri := fmt.Sprintf("/v1/%s/%s", req.Route, req.Value)
	return fmt.Sprintf("%s%s", url, uri)
}

func IrisEnrichURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	var _type string
	switch req.Type {
	case "domain":
		_type = "domain"
	case "ipv4":
		_type = "ip"
	case "ipv6":
		_type = "ip"
	case "url":
		_type = "url"
	case "email":
		_type = "email"
	default:
		_type = "domain"
	}
	uri := fmt.Sprintf("/v1/%v/?%v=%v&api_username=%v&api_key=%v", req.Route, _type, req.Value, uname, key)
	// sig := Sign(uname, key, time, uri)
	return fmt.Sprintf("%s%s", url, uri)
}

func IrisPivotURLBuilder(thisUrl, uname, key, time string, req ProxyRequest) string {
	uri := fmt.Sprintf("/v1/%s/%s", req.Route, req.Value)
	return fmt.Sprintf("%s%s", thisUrl, uri)
}

func (s *Server) DomainToolsHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}
	var uname, key, uri, thisUrl, info string
	var resp []byte
	myAuth := ep.GetAuth()
	switch myAuth.(type) {
	case *BasicAuth:
		uname, key = myAuth.(*BasicAuth).GetInfo()
	default:
		uname, key = "", ""
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if req.Route != "" {
		uri = fmt.Sprintf("/v1/%s/%s", req.Route, req.Value)
	} else {
		uri = fmt.Sprintf("/v1/%s", req.Value)
	}
	sig := Sign(uname, key, timestamp, uri)
	switch req.Route {
	case "whois":
		thisUrl = WhoIsURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-investigate":
		thisUrl = IrisInvestigateURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-profile":
		thisUrl = IrisProfileURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-detect":
		thisUrl = IrisDetectURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-enrich":
		thisUrl = IrisEnrichURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-pivot":
		thisUrl = IrisPivotURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	default:
		uri = fmt.Sprintf("/v1/%s", req.Value)
		thisUrl = fmt.Sprintf("%s%s?api_username=%s&signature=%s&timestamp=%s", ep.GetURL(), uri, uname, sig, timestamp)
	}
	s.LogInfo(fmt.Sprintf("domaintools url: %s", thisUrl))
	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		return nil, err
	}

	resp = ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("domaintools", req.TransactionID, resp)
	var response vendors.DomainToolsIrisEnrichResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		var nextTry map[string]interface{}
		err := json.Unmarshal(resp, &nextTry)
		if err != nil {
			return nil, err
		}
		val, ok := nextTry["response"]
		if !ok {
			return nil, fmt.Errorf("bad response")
		}
		newResponse := val.(map[string]interface{})
		results, ok := newResponse["results_count"]
		if !ok {
			return nil, fmt.Errorf("bad response")
		}
		switch results.(type) {
		case float64:
			return json.Marshal(SummarizedEvent{
				Timestamp:  time.Now(),
				Background: "has-background-primary-dark",
				Info:       fmt.Sprintf("domaintools results count was %v", results),
				From:       req.To,
				Value:      req.Value,
				Link:       req.TransactionID,
				Matched:    true,
				AttrCount:  int(results.(float64)),
			})
		default:
			return json.Marshal(SummarizedEvent{
				Timestamp:  time.Now(),
				Background: "has-background-primary-dark",
				Matched:    false,
				Info:       "domaintools returned a bad response",
				From:       req.To,
				Value:      req.Value,
				Link:       req.TransactionID,
			})
		}

	}
	if response.Response.LimitExceeded {
		info = "domaintools rate limit exceeded"
		return json.Marshal(SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-info",
			Info:       info,
			From:       req.To,
			Value:      req.Value,
			Link:       req.TransactionID,
		})
	}
	if response.Response.ResultsCount == 0 {
		info = "domaintools returned no hits for that value"
		return json.Marshal(SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-primary-dark",
			Info:       info,
			From:       req.To,
			Value:      req.Value,
			Link:       req.TransactionID,
		})
	}
	info = "domaintools returned some hits for that value"
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
		Matched:    true,
	}
	return json.Marshal(sum)
	// return resp, nil
}

func (s *Server) DomainToolsClassicHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}
	var uname, key, uri, thisUrl, info string
	var resp []byte
	myAuth := ep.GetAuth()
	switch myAuth.(type) {
	case *BasicAuth:
		uname, key = myAuth.(*BasicAuth).GetInfo()
	default:
		uname, key = "", ""
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	sig := Sign(uname, key, timestamp, uri)
	switch req.Route {
	case "whois":
		thisUrl = WhoIsURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	default:
		uri = fmt.Sprintf("/v1/%s", req.Value)
		thisUrl = fmt.Sprintf("%s%s?api_username=%s&signature=%s&timestamp=%s", ep.GetURL(), uri, uname, sig, timestamp)
	}
	s.LogInfo(fmt.Sprintf("domaintools url: %s", thisUrl))
	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		return nil, err
	}

	resp = ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("domaintools", req.TransactionID, resp)
	var response vendors.DomainProfileResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		var nextTry map[string]interface{}
		err := json.Unmarshal(resp, &nextTry)
		if err != nil {
			return nil, err
		}
		val, ok := nextTry["response"]
		if !ok {
			return nil, fmt.Errorf("bad response")
		}
		newResponse := val.(map[string]interface{})
		results, ok := newResponse["results_count"]
		if !ok {
			return nil, fmt.Errorf("bad response")
		}
		switch results.(type) {
		case float64:
			return json.Marshal(SummarizedEvent{
				Timestamp:  time.Now(),
				Background: "has-background-warning",
				Info:       fmt.Sprintf("domaintools results count was %v", results),
				From:       req.To,
				Value:      req.Value,
				Link:       req.TransactionID,
				Matched:    true,
				AttrCount:  int(results.(float64)),
			})
		default:
			return json.Marshal(SummarizedEvent{
				Timestamp:  time.Now(),
				Background: "has-background-primary-dark",
				Matched:    false,
				Info:       "domaintools returned a bad response",
				From:       req.To,
				Value:      req.Value,
				Link:       req.TransactionID,
			})
		}

	}
	info = fmt.Sprintf("domaintools returned profile data for %v (%v)", response.Response.Server.IPAddress, response.Response.Registrant.Name)
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
		Matched:    true,
	}
	return json.Marshal(sum)
	// return resp, nil
}

func (s *Server) ParseOtherMispResponse(req ProxyRequest, response []vendors.MispEvent) ([]byte, error) {
	// fmt.Println("ParseOtherMispResponse")
	if len(response) != 0 {
		if len(response) > 1 {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Info:          "received multiple hits for the given value",
				Background:    "has-background-warning",
				From:          req.To,
				ID:            "multiple hits",
				AttrCount:     attrs,
				ThreatLevelID: "0",
				Value:         req.Value,
				Link:          req.TransactionID,
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		} else {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Background:    "has-background-warning",
				From:          req.To,
				ID:            response[0].ID,
				AttrCount:     attrs,
				ThreatLevelID: response[0].ThreatLevelID,
				Value:         req.Value,
				Info:          response[0].Info,
				Link:          req.TransactionID,
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		}
	}
	return json.Marshal(SummarizedEvent{
		Timestamp:     time.Now(),
		Background:    "has-background-primary-dark",
		Info:          "no hits for the given value",
		From:          req.To,
		ID:            "no hits",
		AttrCount:     0,
		ThreatLevelID: "0",
		Value:         req.Value,
		Link:          req.TransactionID,
	})
}

func (s *Server) ParseCorrectMispResponse(req ProxyRequest, response vendors.MispEventResponse) ([]byte, error) {
	if len(response.Response) != 0 {
		if len(response.Response) > 1 {
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Info:          "received multiple hits for the given value",
				Background:    "has-background-warning",
				From:          req.To,
				ID:            "multiple",
				Value:         req.Value,
				AttrCount:     0,
				ThreatLevelID: "1",
				Link:          req.TransactionID,
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		} else {
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Background:    "has-background-warning",
				Info:          response.Response[0].Event.Info,
				From:          req.To,
				ID:            response.Response[0].Event.ID,
				Value:         req.Value,
				AttrCount:     len(response.Response[0].Event.Attribute),
				ThreatLevelID: response.Response[0].Event.ThreatLevelID,
				Link:          req.TransactionID,
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		}
	}
	return json.Marshal(SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-primary-dark",
		Info:       "no hits for the given value",
		From:       req.To,
		ID:         "no hits",
		Value:      req.Value,
		Link:       req.TransactionID,
	})
}

type ErrorMessage struct {
	Error bool   `json:"error"`
	Info  string `json:"info"`
	Time  int64  `json:"time"`
}

func (s *Server) VirusTotalHelper(req ProxyRequest) ([]byte, error) {
	// var em ErrorMessage
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("VirusTotalHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
		// return nil, fmt.Errorf("target not found")
	}

	thisUrl := fmt.Sprintf("%s/%s/%s", ep.GetURL(), req.Route, req.Value)
	// fmt.Println("virus total url", url, req)
	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		s.Log.Println("VirusTotalHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
		// return nil, err
	}

	// request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		s.Log.Println("VirusTotalHelper: got a zero length response")
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("virustotal", req.TransactionID, resp)

	var response vendors.VirusTotalResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		s.Log.Println("VirusTotalHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	info := fmt.Sprintf(`harmless: %d, malicious: %d, suspicious: %d, undetected: %d, timeout: %d`, response.Data.Attributes.LastAnalysisStats.Harmless, response.Data.Attributes.LastAnalysisStats.Malicious, response.Data.Attributes.LastAnalysisStats.Suspicious, response.Data.Attributes.LastAnalysisStats.Undetected, response.Data.Attributes.LastAnalysisStats.Timeout)
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       info,
		From:       req.To,
		Value:      response.Data.ID,
		Link:       req.TransactionID,
		// Link:       fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
		Matched: true,
	}
	return json.Marshal(sum)
	// return resp, nil
}

// func (s *Server) VmRayHelper(req ProxyRequest) ([]byte, error) {

// }

func (s *Server) VmRayFileSubmissionHelper(name string, file UploadHandler) ([]byte, error) {
	ep, ok := s.Targets["vmray"]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}

	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "rest/sample/submit")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("sample_file", name)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, bytes.NewReader(file.Data))
	if err != nil {
		return nil, err
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", thisUrl, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	resp := ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	// go s.addStat(ep.GetURL(), float64(len(resp)))
	return resp, nil

}

func (s *Server) LiveryHelper2(name string, file UploadHandler) ([]byte, error) {
	chunkSize := 1024 * 1024
	totalChunks := (len(file.Data) + chunkSize - 1) / chunkSize
	ep, ok := s.Targets["livery"]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "/upload-chunk")
	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(file.Data) {
			end = len(file.Data)
		}
		part := file.Data[start:end]
		// Upload the chunk
		isLastChunk := i == totalChunks-1
		req, err := http.NewRequest("POST", thisUrl, bytes.NewBuffer(part))
		if err != nil {
			return nil, fmt.Errorf("request error: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-File-ID", file.ID)
		req.Header.Set("X-Filename", name)
		req.Header.Set("X-Last-Chunk", strconv.FormatBool(isLastChunk))
		resp := ep.Do(req)
		if len(resp) == 0 {
			return nil, fmt.Errorf("got a zero length response")
		}
		s.Log.Println(string(resp))
		if !isLastChunk {
			// If not the last chunk, we can continue to the next chunk
			continue
		}
		s.Log.Printf("LiveryHelper: uploaded chunk %d of %d for file %s", i+1, totalChunks, name)
		return resp, nil
	}
	s.Log.Println("LiveryHelper: all chunks uploaded successfully")
	return nil, nil
}

type ResultsRequest struct {
	FileID string `json:"file_id"`
}

// LiveryHelper handles the chunked upload of a file and then fetches its analysis results.
// It sends the file data in chunks to the "/upload-chunk" endpoint and, upon completion,
// makes a POST request to the "/results" endpoint with a JSON payload to retrieve analysis data.
func (s *Server) LiveryHelper(name string, file UploadHandler) ([]byte, error) {
	const chunkSize = 1024 * 1024
	totalChunks := (len(file.Data) + chunkSize - 1) / chunkSize

	ep, ok := s.Targets["livery"]
	if !ok {
		return nil, fmt.Errorf("target 'livery' not found in server targets")
	}

	uploadUrl := fmt.Sprintf("%s/upload-chunk", ep.GetURL())
	s.Log.Printf("LiveryHelper: Starting upload for file '%s' (ID: %s) to %s", name, file.ID, uploadUrl)

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(file.Data) {
			end = len(file.Data)
		}
		part := file.Data[start:end]

		isLastChunk := i == totalChunks-1

		req, err := http.NewRequest("POST", uploadUrl, bytes.NewBuffer(part))
		if err != nil {
			return nil, fmt.Errorf("failed to create upload request for chunk %d: %w", i, err)
		}

		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-File-ID", file.ID)
		req.Header.Set("X-Filename", name)
		req.Header.Set("X-Last-Chunk", strconv.FormatBool(isLastChunk))
		req.ContentLength = int64(len(part))

		respBodyBytes := ep.Do(req)
		if len(respBodyBytes) == 0 {
			return nil, fmt.Errorf("received an empty or error response from server for chunk %d of file '%s'", i+1, name)
		}
		s.Log.Printf("LiveryHelper: Uploaded chunk %d/%d for file '%s'. Server response: %s", i+1, totalChunks, name, strings.TrimSpace(string(respBodyBytes)))

		if isLastChunk {
			// file.ID = strings.TrimSpace(string(respBodyBytes))
			s.Log.Printf("LiveryHelper: All chunks uploaded successfully for file '%s' (ID: %s). Server acknowledged with final ID: %s", name, file.ID, file.ID)
		}
	}

	time.Sleep(100 * time.Millisecond)
	resultsReqBody := ResultsRequest{FileID: file.ID}
	jsonBody, err := json.Marshal(resultsReqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results request body for file ID '%s': %w", file.ID, err)
	}

	resultsUrl := fmt.Sprintf("%s/results", ep.GetURL())
	s.Log.Printf("LiveryHelper: Attempting to fetch analysis results for FileID '%s' from %s", file.ID, resultsUrl)

	// Create a POST request for fetching results with JSON payload
	resultsReq, err := http.NewRequest("POST", resultsUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create results fetch request for file ID '%s': %w", file.ID, err)
	}
	resultsReq.Header.Set("Content-Type", "application/json")
	resultsReq.ContentLength = int64(len(jsonBody))

	resultsRespBodyBytes := ep.Do(resultsReq)
	if len(resultsRespBodyBytes) == 0 {
		return nil, fmt.Errorf("received an empty or error response from /results for file ID '%s'", file.ID)
	}

	s.Log.Printf("LiveryHelper: Successfully fetched analysis results for FileID '%s'. Response length: %d bytes", file.ID, len(resultsRespBodyBytes))
	return resultsRespBodyBytes, nil
}

type matchResponse struct {
	Matched bool   `json:"matched"`
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	ID      int    `json:"id,omitempty"`
	Created int64  `json:"created,omitempty"`
}

func (s *Server) DeepFryHelper(req ProxyRequest) ([]byte, error) {

	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("DeepFryHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}

	thisUrl := fmt.Sprintf("%s/search", ep.GetURL())
	// fmt.Println("deep fry url", url, req)
	data := struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}{
		Kind:  req.Type,
		Value: req.Value,
	}

	out, err := json.Marshal(data)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	// fmt.Println(req, data)
	request, err := http.NewRequest("POST", thisUrl, bytes.NewBuffer(out))
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}

	// request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("deepfry", req.TransactionID, resp)
	var response matchResponse
	var sum SummarizedEvent
	err = json.Unmarshal(resp, &response)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	if !response.Matched {
		s.Log.Println("DeepFryHelper: no hits")
		return CreateAndWriteSummarizedEvent(req, false, "no hits")
	}
	s.Log.Printf("DeepFryHelper: found %s with id %d", response.Value, response.ID)
	sum = SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       fmt.Sprintf("found %s with id %d", response.Value, response.ID),
		From:       req.To,
		Value:      response.Value,
		Link:       req.TransactionID,
		Matched:    true,
	}

	return json.Marshal(sum)
}

func (s *Server) MispHelper(req ProxyRequest) ([]byte, error) {
	var output GenericOut
	output.Type = req.Type
	output.Value = req.Value

	out, err := json.Marshal(output)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}

	ep, ok := s.Targets[req.To]
	if !ok {
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	go s.addStat(ep.GetURL(), float64(len(out)))

	request, err := http.NewRequest("POST", thisUrl, bytes.NewBuffer(out))

	if err != nil {
		fmt.Println("request error", err)
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return CreateAndWriteSummarizedEvent(req, true, "zero length response")
	}
	go s.AddResponse("misp", req.TransactionID, resp)

	var response vendors.MispEventResponse
	err = json.Unmarshal(resp, &response)

	if err != nil {
		var e []vendors.MispEvent
		err := json.Unmarshal(resp, &e)
		if err != nil {
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
		}

		resp, err = s.ParseOtherMispResponse(req, e)
		if err != nil {
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
		}
		return resp, nil
	}
	resp, err = s.ParseCorrectMispResponse(req, response)
	if err != nil {
		fmt.Println("no hits", err)
		badNews := SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-primary-dark",
			From:       req.To,
			ID:         "no hits",
			Value:      req.Value,
			Link:       req.TransactionID,
		}
		return json.Marshal(badNews)
	}
	return resp, nil
}

func DeleteConfigFile(fh string) error {
	err := os.Remove(fh)
	if err != nil {
		return err
	}
	return nil
}

func crowdstrikeBodyBuilder(req ProxyRequest) ([]byte, error) {
	var csr vendors.CSIndicatorRequest
	csr.Filter = fmt.Sprintf("type:'%s' AND value:'%s'", req.Type, req.Value)
	// TODO work out sort later
	return json.Marshal(csr)
}

func (s *Server) CrowdstrikeHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("CrowdstrikeHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}
	var thisType string
	switch req.Type {
	case "domain":
		thisType = "domain"
	case "ipv4":
		thisType = "ip_address"
	case "ipv6":
		thisType = "ip_address"
	case "url":
		thisType = "url"
	case "md5":
		thisType = "hash_md5"
	case "sha256":
		thisType = "hash_sha256"
	case "sha1":
		thisType = "hash_sha1"
	default:
		s.Log.Printf("CrowdstrikeHelper: unsupported type %s, TransactionID: %s", req.Type, req.TransactionID)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("unsupported type: %s", req.Type))
	}
	filter := vendors.CSFalconFilterBuilder(thisType, req.Value)
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "intel/combined/indicators/v1")
	indicatorUrl := fmt.Sprintf("%s?filter=%s", thisUrl, url.QueryEscape(filter))
	request, err := http.NewRequest("GET", indicatorUrl, nil)
	if err != nil {
		s.Log.Println("CrowdstrikeHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		s.Log.Println("CrowdstrikeHelper: got a zero length response")
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("crowdstrike", req.TransactionID, resp)
	var response vendors.CSFalconIOCResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		s.Log.Println("CrowdstrikeHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	if len(response.Resources) == 0 {
		s.Log.Println("CrowdstrikeHelper: no hits")
		return CreateAndWriteSummarizedEvent(req, false, "no hits")
	}
	info := `found %d reports (%v) for value with %v labels`
	resc := response.Resources[0]
	reports := strings.Join(resc.Reports, ", ")
	if len(reports) > 100 {
		reports = reports[:100] + "..."
	}
	info = fmt.Sprintf(info, len(resc.Reports), reports, len(resc.Labels))
	// s.Log.Printf("CrowdstrikeHelper: found %d reports (%v) for value with %v labels", len(resc.Reports), reports, len(resc.Labels))
	event := SummarizedEvent{
		AttrCount:  len(resc.Labels),
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
	}
	return json.Marshal(event)

}

func DeepMapCopy(x, y map[string]float64) {
	for k, v := range x {
		y[k] = v
	}
}

func createLineChart(seriesName string, data []float64) *charts.Line {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{Theme: types.ThemePurplePassion}),
	)
	items := make([]opts.LineData, 0)
	xAxis := []string{}
	smoothLine := opts.LineChart{Smooth: opts.Bool(true)}
	for i := 0; i < len(data); i++ {
		xAxis = append(xAxis, strconv.Itoa(i))
		items = append(items, opts.LineData{Value: data[i]})
	}

	line.SetXAxis(xAxis).
		AddSeries(seriesName, items).
		SetSeriesOptions(charts.WithLineChartOpts(smoothLine))
	return line
}

func RemoveTimestamp(sep string, data string) (string, error) {
	parts := strings.Split(data, sep)
	// fmt.Println(parts)
	if len(parts) < 2 {
		return "", fmt.Errorf("bad data")
	}
	tmp := strings.Split(parts[1], ".")
	if len(tmp) < 2 {
		return "", fmt.Errorf("bad data")
	}
	trueFileName := fmt.Sprintf("%s.%s", parts[0], tmp[1])
	return trueFileName, nil
}

type mandiantIndicatorPostReqest struct {
	Requests []struct {
		Values []string `json:"values"`
	} `json:"requests"`
}

type mandiantError struct {
	Error string `json:"error"`
}

func GetAttributedAssociationsString(indicator vendors.MandiantIndicator) string {
	var result strings.Builder

	for i, assoc := range indicator.AttributedAssociations {
		if i > 0 {
			result.WriteString("; ")
		}
		result.WriteString(fmt.Sprintf("Name: %s, Type: %s", assoc.Name, assoc.Type))
	}

	return result.String()
}

func (s *Server) MandiantHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("MandiantHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}
	var postReq mandiantIndicatorPostReqest
	postReq.Requests = []struct {
		Values []string `json:"values"`
	}{
		{
			Values: []string{req.Value},
		},
	}
	// thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	// fmt.Println("mandiant url", url, req)
	out, err := json.Marshal(postReq)
	if err != nil {
		s.Log.Println("MandiantHelper: server error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	request, err := http.NewRequest("POST", ep.GetURL(), bytes.NewBuffer(out))

	if err != nil {
		s.Log.Println("MandiantHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	resp := ep.Do(request)
	if len(resp) == 0 {
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("mandiant", req.TransactionID, resp)

	var response vendors.MandiantIndicatorResponse
	err = json.Unmarshal(resp, &response)
	if err != nil || len(response.Indicators) < 1 {
		var e mandiantError
		err := json.Unmarshal(resp, &e)
		if err != nil {
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
		}
		if e.Error == "Not Found" {
			return CreateAndWriteSummarizedEvent(req, false, "no hits")
		}
		s.Log.Println("MandiantHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	ind := response.Indicators[0]
	attrCount := len(ind.AttributedAssociations)
	info := `mandiant got hits for that value with score %v: %v`
	if len(ind.AttributedAssociations) > 0 {
		info = fmt.Sprintf(info, ind.Mscore, GetAttributedAssociationsString(ind))
	} else {
		info = fmt.Sprintf(info, ind.Mscore, "no attributed associations")
	}

	sum := SummarizedEvent{
		ID:            ind.ID,
		AttrCount:     attrCount,
		ThreatLevelID: strconv.Itoa(ind.ThreatRating.ThreatScore),
		Timestamp:     time.Now(),
		Background:    "has-background-warning",
		Info:          info,
		From:          req.To,
		Value:         req.Value,
		Link:          req.TransactionID,
		// Link:       fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
		Matched: true,
	}
	return json.Marshal(sum)
}

func CreateAndWriteSummarizedEvent(req ProxyRequest, e bool, info string) ([]byte, error) {
	if e {
		return json.Marshal(SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-grey",
			Info:       info,
			From:       req.To,
			ID:         "no hits",
			Value:      req.Value,
			Link:       req.TransactionID,
			Error:      true,
		})
	}
	return json.Marshal(SummarizedEvent{
		Error:      false,
		Background: "has-background-primary-dark",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
		Timestamp:  time.Now(),
	})

}

type UploadHandler struct {
	FileName string        `json:"file_name"`
	SendCh   chan struct{} `json:"-"`
	Complete bool          `json:"complete"`
	ID       string        `json:"id"`
	Data     []byte        `json:"data"`
	FileSize int64         `json:"file_size"`
}

func (u *UploadHandler) WriteToDisk(filename string) error {
	fh, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer fh.Close()
	_, err = fh.Write(u.Data)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

// TODO: targets might work better as a slice of functions to call
type UploadStore struct {
	Targets      map[string]UploadOperator
	ServerConfig *Configuration
	SendCh       chan struct{}
	Files        map[string]UploadHandler
	Memory       *sync.RWMutex
}

func (u *UploadStore) AddFile(id string, Uh UploadHandler) {
	u.Memory.Lock()
	defer u.Memory.Unlock()
	u.Files[id] = Uh
}

func (u *UploadStore) GetFile(id string) (UploadHandler, bool) {
	u.Memory.RLock()
	defer u.Memory.RUnlock()
	file, ok := u.Files[id]
	return file, ok
}

func (u *UploadStore) DeleteFile(id string) {
	u.Memory.Lock()
	defer u.Memory.Unlock()
	delete(u.Files, id)
}

func NewUploadStore(config *Configuration) *UploadStore {
	return &UploadStore{
		Targets:      UploadOperators,
		ServerConfig: config,
		SendCh:       make(chan struct{}, 100),
		Files:        make(map[string]UploadHandler),
		Memory:       &sync.RWMutex{},
	}
}

func (u *UploadStore) FanOut(resch chan ResponseItem, id string, endpoints map[string]*Endpoint, transactionID string) {
	var wg sync.WaitGroup
	u.Memory.RLock()
	file, ok := u.Files[id]
	u.Memory.RUnlock()
	if !ok {
		fmt.Println("File not found in UploadStore:", id)
		return
	}
	for name, target := range endpoints {
		// fmt.Println("FanOut: working on", name, target.GetURL())
		kind, ok := u.Targets[name]
		if !ok {
			fmt.Println("(can continue) UploadStore: target not found in UploadOperators:", name)
			continue
		}
		wg.Add(1)
		go func(c chan ResponseItem, t *Endpoint, f UploadHandler, k UploadOperator, i string) {
			defer wg.Done()
			// this was previously resch not c
			err := k(c, f, *t, i)
			if err != nil {
				fmt.Println("UploadStore: error in upload operator for target", name, ":", err)
				// c <- ResponseItem{}
			}

		}(resch, target, file, kind, transactionID)
	}
	wg.Wait()
}

// 48646fb84908c16c4b13b0fb4d720549fd0e4fdde8b9bd1276127719659ce798

func (s *Server) addMispAttribute(eventID, attrType, attrValue, category, distribution, comment string, toIDS *bool) ([]byte, error) {
	defer s.addStat("add_attribute_internal_calls", 1)
	start := time.Now()
	defer func() {
		s.Log.Println("addMispAttribute call took", time.Since(start))
	}()

	if eventID == "" {
		return nil, fmt.Errorf("eventID is required")
	}
	if attrType == "" {
		return nil, fmt.Errorf("attribute type is required")
	}
	if attrValue == "" {
		return nil, fmt.Errorf("attribute value is required")
	}

	mispTarget, ok := s.Targets["misp"]
	if !ok {
		return nil, fmt.Errorf("misp endpoint configuration not found in Targets")
	}

	// Set defaults
	if category == "" {
		category = "Network activity"
	}
	if distribution == "" {
		distribution = "0"
	}
	finalToIDS := true
	if toIDS != nil {
		finalToIDS = *toIDS
	}

	attributePayload := AddAttrSchema{
		EventID:      eventID,
		Category:     category,
		Type:         attrType,
		Value:        attrValue,
		ToIDS:        finalToIDS,
		UUID:         uuid.New().String(),
		Distribution: distribution,
		Comment:      comment,
	}

	payloadBytes, err := json.Marshal(attributePayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attribute payload: %w", err)
	}

	url := fmt.Sprintf("%s/attributes/add/%s", mispTarget.GetURL(), eventID)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create MISP attribute request: %w", err)
	}
	// Headers like Content-Type, Accept, and Authorization should be handled by mispTarget.Do or set here
	// request.Header.Set("Content-Type", "application/json")
	// request.Header.Set("Accept", "application/json")
	// request.Header.Set("Authorization", "YOUR_MISP_API_KEY") // Handled by Endpoint.Do in this example

	s.Log.Println("Sending add attribute request to MISP:", url, "Payload:", string(payloadBytes))
	respBody := mispTarget.Do(request)

	s.Log.Println("Successfully added attribute to MISP event", eventID, ". Response:", string(respBody))
	return respBody, nil
}

func (s *Server) createMispEvent(eventDetails vendors.MispEvent) (string, []byte, error) {
	defer s.addStat("create_event_internal_calls", 1)
	start := time.Now()
	defer func() {
		s.Log.Println("createMispEvent call took", time.Since(start))
	}()

	if eventDetails.Info == "" {
		return "", nil, fmt.Errorf("event info is required to create an event")
	}

	// Apply defaults if not provided in eventDetails
	if eventDetails.Distribution == "" {
		eventDetails.Distribution = "0"
	}
	if eventDetails.ThreatLevelID == "" {
		eventDetails.ThreatLevelID = "4"
	}
	if eventDetails.Analysis == "" {
		eventDetails.Analysis = "0"
	}
	if eventDetails.Date == "" {
		eventDetails.Date = time.Now().Format("2006-01-02")
	}

	mispTarget, ok := s.Targets["misp"]
	if !ok {
		return "", nil, fmt.Errorf("misp endpoint configuration not found in Targets")
	}

	url := fmt.Sprintf("%s/events", mispTarget.GetURL())

	payloadBytes, err := json.Marshal(eventDetails)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal event creation payload: %w", err)
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create MISP event request: %w", err)
	}
	// Headers handled by mispTarget.Do in this example

	s.Log.Println("Sending create event request to MISP:", url, "Payload:", string(payloadBytes))
	respBody := mispTarget.Do(request)

	// Parse the response to get the event ID
	var mispResponse vendors.MispEventResponse
	if err := json.Unmarshal(respBody, &mispResponse); err != nil {
		s.Log.Println("Failed to unmarshal MISP event creation response:", err, "Body:", string(respBody))
		return "", respBody, fmt.Errorf("failed to unmarshal MISP event creation response: %w. Body: %s", err, string(respBody))
	}
	if len(mispResponse.Response) == 0 {
		s.Log.Println("MISP event creation response is empty")
		return "", respBody, fmt.Errorf("misp event creation response is empty")
	}
	eventID := mispResponse.Response[0].Event.ID
	s.Log.Println("Successfully created MISP event with ID:", eventID, ". Response:", string(respBody))
	return eventID, respBody, nil
}

func (s *Server) SplunkHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("SplunkHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}

	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "services/search/jobs")
	// thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "services/search/jobs/export")
	// fmt.Println("splunk url", url, req)
	searchString := `search index=main sourcetype=syslog process=threatco value="%s" earliest=-1d latest=now`
	searchString = fmt.Sprintf(searchString, req.Value)
	data := struct {
		Search string `json:"search"`
		Output string `json:"output_mode"`
	}{
		Search: searchString,
		Output: "json",
	}
	out, err := json.Marshal(data)
	if err != nil {
		s.Log.Println("SplunkHelper: server error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	request, err := http.NewRequest("POST", thisUrl, bytes.NewBuffer(out))
	if err != nil {
		s.Log.Println("SplunkHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}

	request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("splunk", req.TransactionID, resp)

	var response vendors.SplunkExportResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		s.Log.Println("SplunkHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}

	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       "under development",
		From:       req.To,
		Value:      req.Value,
		ID:         "under dev",
		Link:       req.TransactionID,
	}
	return json.Marshal(sum)
}

// Target represents a Splunk target (adjust as needed)
type Target struct {
	URL      string
	Username string
	Password string
}

// GetURL returns the target's URL
func (t Target) GetURL() string {
	return t.URL
}

// ErrorXMLResponse represents a potential XML error response
type ErrorXMLResponse struct {
	XMLName  xml.Name `xml:"response"`
	Messages []struct {
		Text string `xml:"text"`
	} `xml:"messages>msg"`
}

// SearchResult represents an individual search result event
type SearchResult struct {
	Raw        string `json:"_raw"`
	Time       string `json:"_time"`
	Host       string `json:"host"`
	Source     string `json:"source"`
	SourceType string `json:"sourcetype"`
	Process    string `json:"process"`
	Value      string `json:"value"`
}

// StreamResult represents the JSON structure for export endpoint
type StreamResult struct {
	Result SearchResult `json:"result"`
}

// SplunkHelper searches Splunk for events matching the request
func (s *Server) SplunkHelper2(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("SplunkHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}

	// Use the export endpoint for streaming JSON
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "services/search/jobs/export")
	searchString := `search index=main sourcetype=syslog process=threatco value="%s" earliest=-1d latest=now`
	searchString = fmt.Sprintf(searchString, req.Value)
	data := url.Values{
		"search":      {searchString},
		"output_mode": {"json"},
	}

	// Alternative with spath if JSON fields are not extracted:
	// searchString := fmt.Sprintf(`search index=main sourcetype=syslog process=threatco earliest=-1d latest=now | spath input=_raw | search value="%s"`, req.Value)
	// data := url.Values{
	//     "search":      {searchString},
	//     "output_mode": {"json"},
	// }

	request, err := http.NewRequest("POST", thisUrl, bytes.NewBufferString(data.Encode()))
	if err != nil {
		s.Log.Println("SplunkHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	myAuth := ep.GetAuth()
	switch myAuth.(type) {
	case *BasicAuth:
		uname, pass := myAuth.(*BasicAuth).GetInfo()
		request.SetBasicAuth(uname, pass)
	default:
		fmt.Println("SplunkHelper: unsupported authentication type")
		return CreateAndWriteSummarizedEvent(req, true, "unsupported authentication type:")
	}
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		s.Log.Println("SplunkHelper: request execution error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request execution error %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.Log.Println("SplunkHelper: failed to read error response", err)
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("failed to read error response %v", err))
		}
		// Attempt to parse XML error response
		var xmlErr ErrorXMLResponse
		if err := xml.Unmarshal(body, &xmlErr); err == nil && len(xmlErr.Messages) > 0 {
			s.Log.Println("SplunkHelper: API error", xmlErr.Messages[0].Text)
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("API error: %s", xmlErr.Messages[0].Text))
		}
		s.Log.Println("SplunkHelper: unexpected status code", resp.StatusCode, string(body))
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("unexpected status code %d: %s", resp.StatusCode, string(body)))
	}

	// Collect streaming JSON results
	var results []SearchResult
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var streamResult StreamResult
		if err := json.Unmarshal([]byte(line), &streamResult); err != nil {
			s.Log.Println("SplunkHelper: failed to decode JSON line", err, line)
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("failed to decode JSON line: %v", err))
		}
		results = append(results, streamResult.Result)
	}

	if err := scanner.Err(); err != nil {
		s.Log.Println("SplunkHelper: error reading stream", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error reading stream: %v", err))
	}

	// Marshal results to []byte for return
	out, err := json.Marshal(results)
	if err != nil {
		s.Log.Println("SplunkHelper: failed to marshal results", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("failed to marshal results: %v", err))
	}
	go s.addStat(ep.GetURL(), float64(len(out)))
	go s.AddResponse("splunk", req.TransactionID, out)

	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       fmt.Sprintf("found %d events for value", len(results)),
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
		AttrCount:  len(results),
		Matched:    true,
	}
	out, err = json.Marshal(sum)
	if err != nil {
		s.Log.Println("SplunkHelper: failed to marshal summary event", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("failed to marshal summary event: %v", err))
	}

	return out, nil
}

func CheckConnectivity(url string) error {
	parts := strings.Split(url, ":")
	cleanUrl := parts[0]
	fmt.Println(url, "Checking connectivity to", cleanUrl, parts)
	// test fqdn
	ips, err := net.LookupIP(cleanUrl)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", cleanUrl, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %s", cleanUrl)
	}
	fmt.Println("Resolved IPs for", cleanUrl, ":", ips)
	conn, err := net.DialTimeout("tcp", url, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", url, err)
	}
	defer conn.Close()
	fmt.Println("Successfully connected to", url)
	return nil
}
