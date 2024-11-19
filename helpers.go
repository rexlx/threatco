package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rexlx/threatco/vendors"
)

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
		Background: "has-background-warning",
		Info:       "no hits for the given value",
		From:       req.To,
		ID:         "no hits",
		Value:      req.Value,
		Link:       req.TransactionID,
	})
}

func (s *Server) VirusTotalHelper(req ProxyRequest) ([]byte, error) {
	ep, ok := s.Targets[req.To]
	if !ok {
		fmt.Println("target not found")
		return nil, fmt.Errorf("target not found")
	}

	url := fmt.Sprintf("%s/%s/%s", ep.GetURL(), req.Route, req.Value)

	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		fmt.Println("request error", err)
		return nil, err
	}

	// request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("rate limited")
	}
	go s.addStat(url, float64(len(resp)))
	go s.AddResponse(req.TransactionID, resp)

	var response vendors.VirusTotalResponse
	err = json.Unmarshal(resp, &response)
	if err != nil {
		fmt.Println("couldnt unmarshal response into vendors.VirusTotalResponse")
		return nil, err
	}
	info := fmt.Sprintf(`harmless: %d, malicious: %d, suspicious: %d, undetected: %d, timeout: %d`, response.Data.Attributes.LastAnalysisStats.Harmless, response.Data.Attributes.LastAnalysisStats.Malicious, response.Data.Attributes.LastAnalysisStats.Suspicious, response.Data.Attributes.LastAnalysisStats.Undetected, response.Data.Attributes.LastAnalysisStats.Timeout)
	sum := SummarizedEvent{
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

func (s *Server) DeepFryHelper(req ProxyRequest) ([]byte, error) {
	fmt.Println("DeepFryHelper")
	ep, ok := s.Targets[req.To]
	if !ok {
		fmt.Println("target not found")
		return nil, fmt.Errorf("target not found")
	}

	url := fmt.Sprintf("%s/get/ip4", ep.GetURL())

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
		fmt.Println("json marshal error", err)
		return nil, err
	}
	fmt.Println(req, data)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))
	if err != nil {
		fmt.Println("request error", err)
		return nil, err
	}

	// request.Header.Set("Content-Type", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("rate limited")
	}
	go s.addStat(url, float64(len(resp)))
	go s.AddResponse(req.TransactionID, resp)
	fmt.Println("DeepFryHelper", string(resp))
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
		fmt.Println("couldnt unmarshal response into vendors.DeepFyResponse", string(resp))
		return nil, err
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
		fmt.Println("json marshal error", err)
		return nil, err
	}

	ep, ok := s.Targets[req.To]
	if !ok {
		fmt.Println("target not found")
		return nil, fmt.Errorf("target not found")
	}
	url := fmt.Sprintf("%s/%s", ep.GetURL(), req.Route)
	go s.addStat(url, float64(len(out)))

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(out))

	if err != nil {
		fmt.Println("request error", err)
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp := ep.Do(request)
	if len(resp) == 0 {
		return nil, fmt.Errorf("rate limited")
	}
	go s.AddResponse(req.TransactionID, resp)

	var response vendors.Response
	err = json.Unmarshal(resp, &response)

	if err != nil {
		var e []vendors.Event
		err := json.Unmarshal(resp, &e)
		if err != nil {
			fmt.Println("couldnt unmarshal response into vendors.Response or []vendors.Event")
			return nil, err
		}

		resp, err = s.ParseOtherMispResponse(req, e)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		return resp, nil
	}
	resp, err = s.ParseCorrectMispResponse(req, response)
	if err != nil {
		fmt.Println("no hits", err)
		badNews := SummarizedEvent{
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

func DeepMapCopy(x, y map[string]float64) {
	for k, v := range x {
		y[k] = v
	}
}
