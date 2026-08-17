package internal

import (
	"testing"
)

func TestServiceType_MarshalUnmarshalBinary(t *testing.T) {
	st := ServiceType{
		Name:        "VirusTotal",
		Kind:        "virustotal",
		Key:         "vt-secret-key",
		AuthType:    "apikey",
		MaxRequests: 100,
		RouteMap: []RouteMap{
			{Type: "md5", Route: "files"},
		},
	}

	data, err := st.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	var newSt ServiceType
	if err := newSt.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if newSt.Name != st.Name || newSt.Kind != st.Kind || newSt.Key != st.Key || newSt.MaxRequests != st.MaxRequests {
		t.Errorf("unmarshaled ServiceType mismatch: got %+v, want %+v", newSt, st)
	}
	if len(newSt.RouteMap) != len(st.RouteMap) || newSt.RouteMap[0].Route != st.RouteMap[0].Route {
		t.Errorf("RouteMap mismatch: got %+v", newSt.RouteMap)
	}
}

func TestSupportedServices(t *testing.T) {
	if len(SupportedServices) == 0 {
		t.Fatal("SupportedServices slice should not be empty")
	}

	foundVT := false
	for _, svc := range SupportedServices {
		if svc.Kind == "virustotal" {
			foundVT = true
			if len(svc.RouteMap) == 0 {
				t.Error("virustotal service should have route maps")
			}
		}
	}

	if !foundVT {
		t.Error("virustotal service not found in SupportedServices")
	}
}
