package main

import (
	"bytes"
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
	"misp":        MispProxyHelper,
	"deepfry":     DeepFryProxyHelper,
	"mandiant":    MandiantProxyHelper,
	"virustotal":  VirusTotalProxyHelper,
	"crowdstrike": CrowdstrikeProxyHelper,
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
