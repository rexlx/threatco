package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rexlx/threatco/vendors"
)

func ParseOtherMispResponse(req ProxyRequest, response []vendors.Event) ([]byte, error) {
	// fmt.Println("ParseOtherMispResponse")
	if len(response) != 0 {
		if len(response) > 1 {
			attrs, err := strconv.Atoi(response[0].AttributeCount)
			if err != nil {
				fmt.Println("got bad attr data from misp...")
				attrs = 0
			}
			return json.Marshal(SummarizedEvent{
				Background:    "has-background-primary-dark",
				From:          req.To,
				ID:            "multiple hits",
				AttrCount:     attrs,
				ThreatLevelID: "0",
				Value:         req.Value,
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
			})
		}
	}
	return json.Marshal(SummarizedEvent{
		Background:    "has-background-warning",
		From:          req.To,
		ID:            "no hits",
		AttrCount:     0,
		ThreatLevelID: "0",
		Value:         req.Value,
	})
}

func ParseCorrectMispResponse(req ProxyRequest, response vendors.Response) ([]byte, error) {
	// fmt.Println("ParseCorrectMispResponse")
	if len(response.Response) != 0 {
		if len(response.Response) > 1 {
			return json.Marshal(SummarizedEvent{
				Background:    "has-background-primary-dark",
				From:          req.To,
				ID:            "multiple",
				Value:         req.Value,
				AttrCount:     0,
				ThreatLevelID: "1",
			})
		} else {
			return json.Marshal(SummarizedEvent{
				Background:    "has-background-primary-dark",
				From:          req.To,
				ID:            response.Response[0].Event.ID,
				Value:         req.Value,
				AttrCount:     len(response.Response[0].Event.Attribute),
				ThreatLevelID: response.Response[0].Event.ThreatLevelID,
			})
		}
	}
	return json.Marshal(SummarizedEvent{
		Background: "has-background-warning",
		From:       req.To,
		ID:         "no hits",
	})
}

func (s *Server) Misphelper(req ProxyRequest) ([]byte, error) {
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
	// fmt.Println(string(resp))

	var response vendors.Response
	err = json.Unmarshal(resp, &response)

	if err != nil {
		var e []vendors.Event
		err := json.Unmarshal(resp, &e)

		if err != nil {
			fmt.Println("couldnt unmarshal response into vendors.Response or []vendors.Event")
			return nil, err
		}

		resp, err = ParseOtherMispResponse(req, e)

		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		return resp, nil
	}
	resp, err = ParseCorrectMispResponse(req, response)
	if err != nil {
		fmt.Println(err)
		badNews := SummarizedEvent{
			Background: "has-background-warning",
			From:       req.To,
			ID:         "no hits",
			Value:      req.Value,
		}
		return json.Marshal(badNews)
	}
	return resp, nil
}

//
