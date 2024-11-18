package main

import "encoding/json"

var SupportedServices = []ServiceType{
	{
		Kind:     "misp",
		Type:     []string{"md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "email", "url", "domain", "filepath", "filename"},
		RouteMap: make([]RouteMap, 0),
	},
	{
		Kind:     "deepfry",
		Type:     []string{"ipv4", "ipv6"},
		RouteMap: make([]RouteMap, 0),
	},
	{
		Kind: "virustotal",
		Type: []string{"md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "url", "domain", "filepath", "filename"},
		RouteMap: []RouteMap{
			{
				Type:  "md5",
				Route: "files",
			},
			{
				Type:  "sha1",
				Route: "files",
			},
			{
				Type:  "sha256",
				Route: "files",
			},
			{
				Type:  "sha512",
				Route: "files",
			},
			{
				Type:  "ipv4",
				Route: "ip_addresses",
			},
			{
				Type:  "ipv6",
				Route: "ip_addresses",
			},
			{
				Type:  "url",
				Route: "urls",
			},
			{
				Type:  "domain",
				Route: "domains",
			},
			{
				Type:  "filepath",
				Route: "files",
			},
			{
				Type:  "filename",
				Route: "files",
			},
		},
	},
}

type ServiceType struct {
	Kind     string     `json:"kind"`
	Type     []string   `json:"type"`
	RouteMap []RouteMap `json:"route_map"`
}

type RouteMap struct {
	Type  string `json:"type"`
	Route string `json:"route"`
}

func (s *ServiceType) MarshalBinary() ([]byte, error) {
	return json.Marshal(s)
}

func (s *ServiceType) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, s)
}
