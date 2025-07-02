package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rexlx/threatco/vendors"
)

type ProxyOperator func(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error)

// TODO rethink this tomorrow. it does no good to name these here, they have to built
// based of the config.
var ProxyOperators = map[string]ProxyOperator{
	"misp":                MispProxyHelper,
	"deepfry":             DeepFryProxyHelper,
	"mandiant":            MandiantProxyHelper,
	"virustotal":          VirusTotalProxyHelper,
	"crowdstrike":         CrowdstrikeProxyHelper,
	"splunk":              SplunkProxyHelper,
	"domaintools":         DomainToolsProxyHelper,
	"domaintools-classic": DomainToolsClassicProxyHelper,
	"urlscan":             URLScanProxyHelper,
}

func MispProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
	var output GenericOut
	output.Type = req.Type
	output.Value = req.Value

	out, err := json.Marshal(output)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}

	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)

	//go s.addStat(ep.GetURL(), float64(len(out)))

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
	//go s.AddResponse("misp", req.TransactionID, resp)
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "misp",
		Data:   resp,
		Time:   time.Now(),
	}
	var response vendors.MispEventResponse
	err = json.Unmarshal(resp, &response)

	if err != nil {
		var e []vendors.MispEvent
		err := json.Unmarshal(resp, &e)
		if err != nil {
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
		}

		resp, err = ParseOtherMispResponse(req, e)
		if err != nil {
			return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
		}
		return resp, nil
	}
	resp, err = ParseCorrectMispResponse(req, response)
	if err != nil {
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

func DeepFryProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
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
	// go s.addStat(ep.GetURL(), float64(len(resp)))
	// go s.AddResponse("deepfry", req.TransactionID, resp)
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "deepfry",
		Data:   resp,
		Time:   time.Now(),
	}
	var response matchResponse
	var sum SummarizedEvent
	err = json.Unmarshal(resp, &response)
	if err != nil {
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	if !response.Matched {
		return CreateAndWriteSummarizedEvent(req, false, "no hits")
	}
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

func MandiantProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
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
		fmt.Println("MandiantHelper: server error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("server error %v", err))
	}
	request, err := http.NewRequest("POST", ep.GetURL(), bytes.NewBuffer(out))

	if err != nil {
		fmt.Println("MandiantHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	resp := ep.Do(request)
	if len(resp) == 0 {
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	// go s.addStat(ep.GetURL(), float64(len(resp)))
	// go s.AddResponse("mandiant", req.TransactionID, resp)
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "mandiant",
		Data:   resp,
		Time:   time.Now(),
	}

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
		fmt.Println("MandiantHelper: bad vendor response", err)
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

func VirusTotalProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {

	thisUrl := fmt.Sprintf("%s/%s/%s", ep.GetURL(), req.Route, req.Value)
	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		fmt.Println("VirusTotalHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
		// return nil, err
	}

	// request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		fmt.Println("VirusTotalHelper: got a zero length response")
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "virustotal",
		Data:   resp,
		Time:   time.Now(),
	}

	var response vendors.VirusTotalResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		fmt.Println("VirusTotalHelper: bad vendor response", err)
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

func CrowdstrikeProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
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
		fmt.Printf("CrowdstrikeHelper: unsupported type %s, TransactionID: %s", req.Type, req.TransactionID)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("unsupported type: %s", req.Type))
	}
	filter := vendors.CSFalconFilterBuilder(thisType, req.Value)
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "intel/combined/indicators/v1")
	indicatorUrl := fmt.Sprintf("%s?filter=%s", thisUrl, url.QueryEscape(filter))
	request, err := http.NewRequest("GET", indicatorUrl, nil)
	if err != nil {
		fmt.Println("CrowdstrikeHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		fmt.Println("CrowdstrikeHelper: got a zero length response")
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}

	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "crowdstrike",
		Data:   resp,
		Time:   time.Now(),
	}

	var response vendors.CSFalconIOCResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		fmt.Println("CrowdstrikeHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	if len(response.Resources) == 0 {
		fmt.Println("CrowdstrikeHelper: no hits")
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

func SplunkProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
	// thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "services/search/jobs")
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "services/search/jobs/export")
	// fmt.Println("splunk url", url, req)
	searchString := `search index=main sourcetype=syslog process=threatco value="%s" earliest=-1d latest=now`
	searchString = fmt.Sprintf(searchString, req.Value)
	out := url.Values{}
	out.Set("search", searchString)
	out.Set("output_mode", "json")
	out.Set("earliest_time", "-1d")
	out.Set("latest_time", "now")
	request, err := http.NewRequest("POST", thisUrl, bytes.NewBufferString(out.Encode()))
	if err != nil {
		fmt.Println("SplunkHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// cant use traditional endpoint.Do because of streamed response
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	myAuth := ep.GetAuth()
	switch myAuth.(type) {
	case *BasicAuth:
		uname, key := myAuth.(*BasicAuth).GetInfo()
		request.SetBasicAuth(uname, key)
	default:
		fmt.Println("SplunkHelper: unsupported auth type, using default 'threatco'")
		request.SetBasicAuth("threatco", "threatco")
	}
	resp, err := client.Do(request)
	if err != nil {
		fmt.Println("SplunkHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("SplunkHelper: got a non-200 response", resp.StatusCode)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("got a non-200 response %d", resp.StatusCode))
	}
	var results []SearchResult
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue // skip empty lines
		}
		var res StreamResult
		err := json.Unmarshal([]byte(line), &res)
		if err != nil {
			fmt.Println("SplunkHelper: error unmarshalling line", err)
			continue
		}
		results = append(results, res.Result)
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("SplunkHelper: error reading response body", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error reading response body %v", err))
	}
	if len(results) == 0 {
		fmt.Println("SplunkHelper: no hits found")
		return CreateAndWriteSummarizedEvent(req, false, "no hits found")
	}
	data, err := json.Marshal(results)
	if err != nil {
		fmt.Println("SplunkHelper: error marshalling results", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("error marshalling results %v", err))
	}
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "splunk",
		Data:   data,
		Time:   time.Now(),
	}

	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       fmt.Sprintf("found %d results for value", len(results)),
		From:       req.To,
		Value:      req.Value,
		ID:         "",
		Link:       req.TransactionID,
	}
	return json.Marshal(sum)
}

func DomainToolsClassicProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
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

	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		return nil, err
	}

	resp = ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "domaintools",
		Data:   resp,
		Time:   time.Now(),
	}
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

func DomainToolsProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
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
	request, err := http.NewRequest("GET", thisUrl, nil)

	if err != nil {
		return nil, err
	}

	resp = ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("got a zero length response")
	}
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "domaintools",
		Data:   resp,
		Time:   time.Now(),
	}
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

func URLScanProxyHelper(resch chan ResponseItem, ep Endpoint, req ProxyRequest) ([]byte, error) {
	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "api/v1/search")
	request, err := http.NewRequest("GET", thisUrl, nil)
	if err != nil {
		fmt.Println("URLScanHelper: request error", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("request error %v", err))
	}
	query := request.URL.Query()
	query.Set("q", req.Value)
	query.Set("size", "100")
	query.Add("search_after", "string")
	query.Set("datasource", "scans")
	request.URL.RawQuery = query.Encode()
	resp := ep.Do(request)
	if len(resp) == 0 {
		fmt.Println("URLScanHelper: got a zero length response")
		return CreateAndWriteSummarizedEvent(req, true, "got a zero length response")
	}
	resch <- ResponseItem{
		ID:     req.TransactionID,
		Vendor: "urlscan",
		Data:   resp,
		Time:   time.Now(),
	}
	var response vendors.URLScanSearchResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		fmt.Println("URLScanHelper: bad vendor response", err)
		return CreateAndWriteSummarizedEvent(req, true, fmt.Sprintf("bad vendor response %v", err))
	}
	if len(response.Results) == 0 {
		fmt.Println("URLScanHelper: no hits found")
		return CreateAndWriteSummarizedEvent(req, false, "no hits found")
	}
	info := fmt.Sprintf("found %d results for value", len(response.Results))
	sum := SummarizedEvent{
		Timestamp:  time.Now(),
		Background: "has-background-warning",
		Info:       info,
		From:       req.To,
		Value:      req.Value,
		ID:         "",
		Link:       req.TransactionID,
		Matched:    true,
	}
	return json.Marshal(sum)

}
