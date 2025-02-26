package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
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
	case "domaintools":
		return s.DomainToolsHelper(req)
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

func IrisPivotURLBuilder(url, uname, key, time string, req ProxyRequest) string {
	uri := fmt.Sprintf("/v1/%s/%s", req.Route, req.Value)
	return fmt.Sprintf("%s%s", url, uri)
}

func (s *Server) DomainToolsHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		return nil, fmt.Errorf("target not found")
	}
	var uname, key, uri, url, info string
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
		url = WhoIsURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-investigate":
		url = IrisInvestigateURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-profile":
		url = IrisProfileURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-detect":
		url = IrisDetectURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-enrich":
		url = IrisEnrichURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	case "iris-pivot":
		url = IrisPivotURLBuilder(ep.GetURL(), uname, key, timestamp, req)
	default:
		url = fmt.Sprintf("%s%s?api_username=%s&signature=%s&timestamp=%s", ep.GetURL(), uri, uname, sig, timestamp)
	}

	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	resp := ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	go s.addStat(ep.GetURL(), float64(len(resp)))
	go s.AddResponse("domaintools", req.TransactionID, resp)
	var response vendors.DomainToolsIrisEnrichResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		return nil, err
	}
	if response.Response.LimitExceeded {
		info = "domaintools rate limit exceeded"
		return json.Marshal(SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-warning",
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
			Background: "has-background-warning",
			Info:       info,
			From:       req.To,
			Value:      req.Value,
			Link:       req.TransactionID,
		})
	}
	info = "domaintools returned some hits for that value"
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-primary-dark",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		Link:       req.TransactionID,
		Matched:    true,
	}
	return json.Marshal(sum)
	// return resp, nil
}

func (s *Server) ParseOtherMispResponse(req ProxyRequest, response []vendors.Event) ([]byte, error) {
	// fmt.Println("ParseOtherMispResponse")
	if len(response) != 0 {
		if len(response) > 1 {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			return json.Marshal(SummarizedEvent{
				Timestamp:     time.Now(),
				Info:          "received multiple hits for the given value",
				Background:    "has-background-primary-dark",
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
				Timestamp:     time.Now(),
				Background:    "has-background-primary-dark",
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
		Background:    "has-background-warning",
		Info:          "no hits for the given value",
		From:          req.To,
		ID:            "no hits",
		AttrCount:     0,
		ThreatLevelID: "0",
		Value:         req.Value,
		Link:          req.TransactionID,
	})
}

func (s *Server) ParseCorrectMispResponse(req ProxyRequest, response vendors.Response) ([]byte, error) {
	if len(response.Response) != 0 {
		if len(response.Response) > 1 {
			return json.Marshal(SummarizedEvent{
				Timestamp:     time.Now(),
				Info:          "received multiple hits for the given value",
				Background:    "has-background-primary-dark",
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
				Timestamp:     time.Now(),
				Background:    "has-background-primary-dark",
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
		Background: "has-background-warning",
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

	url := fmt.Sprintf("%s/%s/%s", ep.GetURL(), req.Route, req.Value)
	// fmt.Println("virus total url", url, req)
	request, err := http.NewRequest("GET", url, nil)

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
		Background: "has-background-primary-dark",
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

	url := fmt.Sprintf("%s/%s", ep.GetURL(), "rest/sample/submit")

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
	request, err := http.NewRequest("POST", url, body)
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

func (s *Server) DeepFryHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		s.Log.Println("DeepFryHelper: target not found")
		return CreateAndWriteSummarizedEvent(req, true, "target not found")
	}

	url := fmt.Sprintf("%s/get/ip4", ep.GetURL())
	// fmt.Println("deep fry url", url, req)
	data := struct {
		Message string `json:"message"`
		Value   string `json:"value"`
		Error   bool   `json:"error"`
	}{
		Message: "",
		Value:   req.Value,
	}

	out, err := json.Marshal(data)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	// fmt.Println(req, data)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))
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
	response := struct {
		ID      int    `json:"id"`
		Message string `json:"message"`
		Value   string `json:"value"`
		Error   bool   `json:"error"`
	}{
		Message: "",
		Value:   "",
	}
	err = json.Unmarshal(resp, &response)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	var matched bool
	var id string
	bg := "has-background-dark"
	if !response.Error {
		matched = true
		bg = "has-background-primary-dark"
		id = strconv.Itoa(response.ID)
	}
	fmt.Println(response)
	sum := SummarizedEvent{
		Timestamp:     time.Now(),
		AttrCount:     0,
		ThreatLevelID: "1",
		ID:            id,
		Background:    bg,
		Info:          "that IP looks nosey!",
		From:          req.To,
		Value:         response.Value,
		Link:          req.TransactionID,
		// Link:          fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
		Matched: matched,
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
	url := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	// fmt.Println("misp url", url, req)
	go s.addStat(ep.GetURL(), float64(len(out)))

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))

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

	var response vendors.Response
	err = json.Unmarshal(resp, &response)

	if err != nil {
		var e []vendors.Event
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
			Background: "has-background-warning",
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
	url := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	// fmt.Println("mandiant url", url, req)
	out, err := json.Marshal(postReq)
	if err != nil {
		s.Log.Println("MandiantHelper: server error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))

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
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-primary-dark",
		Info:       "under development",
		From:       req.To,
		Value:      "under development",
		Link:       req.TransactionID,
		// Link:       fmt.Sprintf("%s%s/events/%s", s.Details.FQDN, s.Details.Address, req.TransactionID),
		Matched: true,
	}
	return json.Marshal(sum)
}

func CreateAndWriteSummarizedEvent(req ProxyRequest, e bool, info string) ([]byte, error) {
	if e {
		return json.Marshal(SummarizedEvent{
			Timestamp:  time.Now(),
			Background: "has-background-warning",
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

type UploadStore struct {
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

// func (u *UploadStore) BroadcastUpload(uh UploadHandler)

// func NewUploadHandler
