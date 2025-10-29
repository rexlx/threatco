package main

import (
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
	"github.com/rexlx/threatco/optional"
	"github.com/rexlx/threatco/vendors"
)

func (s *Server) CleanUserServices(u *User) {
	supportedKindsMap := make(map[string]bool)
	newServices := make([]ServiceType, 0)
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	if u == nil || len(u.Services) == 0 {
		return
	}
	for _, svc := range s.Details.SupportedServices {
		supportedKindsMap[svc.Kind] = true
	}

	for _, svc := range u.Services {
		if _, ok := supportedKindsMap[svc.Kind]; ok {
			newServices = append(newServices, svc)
		} else {
			s.Log.Printf("CleanUserServices: removing unsupported service %s for user %s", svc.Kind, u.Email)
		}
	}
	if len(newServices) == 0 {
		s.Log.Printf("CleanUserServices: no supported services left for user %s", u.Email)
		u.Services = make([]ServiceType, 0)
		return
	}
	u.Services = newServices
}

func (s *Server) GetCurrentUserEmail(r *http.Request) string {
	// Example adaptation of your logic:
	tkn, err := s.GetTokenFromSession(r)
	if err != nil {
		return "" // No user logged in
	}
	if tkn != "" {
		tk, e := s.DB.GetTokenByValue(tkn)
		if e != nil {
			return ""
		}
		// We found the user's email!
		return tk.Email
	}
	return "" // Default to empty if no user
}

func MergeJSONData(existingData, newData []byte) ([]byte, error) {
	if len(newData) == 0 {
		return existingData, nil
	}

	if len(existingData) == 0 {
		initialArray := []json.RawMessage{json.RawMessage(newData)}
		return json.Marshal(initialArray)
	}

	var objects []json.RawMessage

	if err := json.Unmarshal(existingData, &objects); err != nil {
		objects = []json.RawMessage{json.RawMessage(existingData)}
	}

	objects = append(objects, json.RawMessage(newData))

	return json.Marshal(objects)
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

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	// Convert to runes to handle multi-byte characters correctly
	runes := []rune(s)
	if len(runes) > length {
		return string(runes[:length])
	}
	return s
}

func ParseOtherMispResponse(req ProxyRequest, response []vendors.MispEvent) ([]byte, error) {
	// fmt.Println("ParseOtherMispResponse")
	if len(response) != 0 {
		if len(response) > 1 {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			info := "received multiple hits: "
			var tLevel int
			for _, r := range response {
				t, err := strconv.Atoi(r.ThreatLevelID)
				if err != nil {
					tLevel += 0
				} else {
					tLevel += t
				}
				info += fmt.Sprintf("ID %s: %s; ", r.ID, r.Info)
			}
			info = truncateString(info, 150)
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Info:          info,
				Background:    "has-background-warning",
				From:          req.To,
				ID:            "multiple hits",
				AttrCount:     attrs,
				ThreatLevelID: tLevel,
				Value:         req.Value,
				Link:          req.TransactionID,
				Type:          req.Type,
				RawLink:       fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		} else {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			tlid, err := strconv.Atoi(response[0].ThreatLevelID)
			if err != nil {
				tlid = 0
			}
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Background:    "has-background-warning",
				From:          req.To,
				ID:            response[0].ID,
				AttrCount:     attrs,
				ThreatLevelID: tlid,
				Value:         req.Value,
				Info:          response[0].Info,
				Link:          req.TransactionID,
				Type:          req.Type,
				RawLink:       fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
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
		AttrCount:  0,
		Value:      req.Value,
		Link:       req.TransactionID,
		Type:       req.Type,
		RawLink:    fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
	})
}

type CheckResponse struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

func (s *Server) SimpleServiceCheck() error {
	start := time.Now()
	s.Memory.Lock()
	servicesToCheck := make([]ServiceType, len(s.Details.SupportedServices))
	copy(servicesToCheck, s.Details.SupportedServices)
	s.Memory.Unlock()

	resch := make(chan CheckResponse, len(servicesToCheck))
	wg := sync.WaitGroup{}

	for _, service := range servicesToCheck {
		if service.URL == "" {
			s.Log.Printf("SimpleServiceCheck: skipping service %s due to empty URL", service.Kind)
			continue
		}
		wg.Add(1)
		go func(name string, url string) {
			defer wg.Done()
			err := TestConnectivity(url)
			if err != nil {
				s.Log.Printf("SimpleServiceCheck: %s is not reachable: %v", name, err)
				resch <- CheckResponse{Name: name, Value: 0.0}
			} else {
				s.Log.Printf("SimpleServiceCheck: %s is reachable", name)
				resch <- CheckResponse{Name: name, Value: 1.0}
			}
		}(service.Kind, service.URL)
	}

	go func() {
		wg.Wait()
		close(resch)
	}()

	s.Log.Printf("SimpleServiceCheck: waiting for results...")
	for res := range resch {
		s.Memory.Lock()
		s.Details.Stats[fmt.Sprintf("health-check-%s", res.Name)] = res.Value
		s.Memory.Unlock()
	}

	s.Log.Printf("SimpleServiceCheck: completed in %s", time.Since(start))
	return nil
}

func ParseCorrectMispResponse(req ProxyRequest, response vendors.MispEventResponse) ([]byte, error) {
	if len(response.Response) != 0 {
		if len(response.Response) > 1 {
			info := "received multiple hits: "
			var tLevel int
			var attrs int
			for _, r := range response.Response {
				info += fmt.Sprintf("ID %s: %s; ", r.Event.ID, r.Event.Info)
				t, err := strconv.Atoi(r.Event.ThreatLevelID)
				if err != nil {
					tLevel += 0
				} else {
					tLevel += t
				}
				a, err := strconv.Atoi(r.Event.AttributeCount)
				if err != nil {
					attrs += 0
				} else {
					attrs += a
				}
			}
			info = truncateString(info, 150)
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Info:          info,
				Background:    "has-background-warning",
				From:          req.To,
				ID:            "multiple",
				Value:         req.Value,
				AttrCount:     attrs,
				ThreatLevelID: tLevel,
				Link:          req.TransactionID,
				Type:          req.Type,
				RawLink:       fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
				// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
			})
		} else {
			tlid, err := strconv.Atoi(response.Response[0].Event.ThreatLevelID)
			if err != nil {
				tlid = 0
			}
			return json.Marshal(SummarizedEvent{
				Matched:       true,
				Timestamp:     time.Now(),
				Background:    "has-background-warning",
				Info:          response.Response[0].Event.Info,
				From:          req.To,
				ID:            response.Response[0].Event.ID,
				Value:         req.Value,
				AttrCount:     len(response.Response[0].Event.Attribute),
				ThreatLevelID: tlid,
				Link:          req.TransactionID,
				Type:          req.Type,
				RawLink:       fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
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
		Type:       req.Type,
		RawLink:    fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
	})
}

type ErrorMessage struct {
	Error bool   `json:"error"`
	Info  string `json:"info"`
	Time  int64  `json:"time"`
}

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

type ResultsRequest struct {
	FileID string `json:"file_id"`
}

// i belive this may be deletable
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

func DeleteConfigFile(fh string) error {
	err := os.Remove(fh)
	if err != nil {
		return err
	}
	return nil
}

func DeepMapCopy(x, y map[string]float64) {
	for k, v := range x {
		y[k] = v
	}
}

func GetDBHost() string {
	host := os.Getenv("DB_HOST")
	if host == "" {
		fmt.Println("DB_HOST not set, using localhost")
		host = "localhost"
	}
	return host
}

func createLineChart(seriesName string, data []Coord) *charts.Line {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{Theme: types.ThemeMacarons, BackgroundColor: "#333"}),
		charts.WithTitleOpts(opts.Title{
			Title: seriesName,
		}),
		// Add a tooltip for better user experience
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{
				Rotate: 45,
			},
		}),
	)

	// Create a slice of the concrete data type, not the interface.
	items := make([]opts.LineData, 0, len(data))
	xAxis := make([]string, 0, len(data))

	// Loop through your data points
	for _, point := range data {
		// 1. Format the Unix timestamp into a human-readable string (e.g., "15:04:05") for the X-axis.
		formattedTime := time.Unix(point.Time, 0).Format("15:04:05")
		xAxis = append(xAxis, formattedTime)

		// 2. Use the 'Value' field for the Y-axis data point.
		items = append(items, opts.LineData{Value: point.Value})
	}

	// Set the X-axis and add the series data to the chart.
	// The AddSeries function can accept a slice of concrete types like []opts.LineData.
	line.SetXAxis(xAxis).
		AddSeries(seriesName, items, charts.WithLineChartOpts(opts.LineChart{Smooth: opts.Bool(true)}))

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
		ThreatLevelID: ind.ThreatRating.ThreatScore,
		Timestamp:     time.Now(),
		Background:    "has-background-warning",
		Info:          info,
		From:          req.To,
		Value:         req.Value,
		Link:          req.TransactionID,
		// Link:       fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
		Matched: true,
		Type:    req.Type,
		RawLink: fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
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
			Type:       req.Type,
			RawLink:    fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
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
		Type:       req.Type,
		RawLink:    fmt.Sprintf("%s/events/%s", req.FQDN, req.TransactionID),
	})

}

type Webhook struct {
	Url      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (w *Webhook) Get() ([]byte, error) {
	if w.Url == "" {
		return nil, fmt.Errorf("webhook URL is empty")
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", w.Url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(w.Username, w.Password)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (w *Webhook) Post(data []byte) error {
	if w.Url == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	client := &http.Client{}
	req, err := http.NewRequest("POST", w.Url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(w.Username, w.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned non-200 status: %d", resp.StatusCode)
	}
	return nil
}

type UploadHandler struct {
	For      string        `json:"for"`
	FileName string        `json:"file_name"`
	SendCh   chan struct{} `json:"-"`
	Complete bool          `json:"complete"`
	ID       string        `json:"id"`
	Data     []byte        `json:"data"`
	FileSize int64         `json:"file_size"`
	WebHook  Webhook       `json:"webhook"`
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
	if file.FileName == "" {
		fmt.Println("File name is empty in UploadStore for ID:", id)
		file.FileName = id
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

func (s *Server) AddMispAttribute(eventID, attrType, attrValue, category, distribution, comment string, toIDS *bool) ([]byte, error) {
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

func (s *Server) CreateMispEvent(eventDetails vendors.MispEvent) (string, []byte, error) {
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
	// fmt.Println("Successfully connected to", url)
	return nil
}

func TestConnectivity(rawURL string) error {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	host, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		host = parsedURL.Host
		switch parsedURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "443"
		}
	}

	address := net.JoinHostPort(host, port)
	// fmt.Printf("Testing connectivity to %s\n", address)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	// fmt.Printf("Successfully connected to %s\n", address)
	return nil
}

type PromptRequest = optional.LlmToolsPromptRequest
