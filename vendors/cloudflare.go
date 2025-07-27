package vendors

import "strings"

type CloudFlareDomainResponse struct {
	Errors   []CloudFlareError   `json:"errors,omitempty"`
	Messages []CloudFlareMessage `json:"messages,omitempty"`
	Success  bool                `json:"success"`
	Result   *CloudFlareResult   `json:"result,omitempty"`
}

type CloudFlareIPResponse struct {
	Errors   []CloudFlareError    `json:"errors,omitempty"`
	Messages []CloudFlareMessage  `json:"messages,omitempty"`
	Success  bool                 `json:"success"`
	Result   []CloudFlareIPResult `json:"result,omitempty"`
}

type CloudFlareError struct {
	Code             int               `json:"code,omitempty"`
	Message          string            `json:"message,omitempty"`
	DocumentationURL string            `json:"documentation_url,omitempty"`
	Source           *CloudFlareSource `json:"source,omitempty"`
}

type CloudFlareMessage struct {
	Code             int               `json:"code,omitempty"`
	Message          string            `json:"message,omitempty"`
	DocumentationURL string            `json:"documentation_url,omitempty"`
	Source           *CloudFlareSource `json:"source,omitempty"`
}

type CloudFlareSource struct {
	Pointer string `json:"pointer,omitempty"`
}

type CloudFlareResult struct {
	AdditionalInformation      *AdditionalInformation `json:"additional_information,omitempty"`
	Application                *Application           `json:"application,omitempty"`
	ContentCategories          []ContentCategory      `json:"content_categories,omitempty"`
	Domain                     string                 `json:"domain,omitempty"`
	InheritedContentCategories []ContentCategory      `json:"inherited_content_categories,omitempty"`
	InheritedFrom              string                 `json:"inherited_from,omitempty"`
	InheritedRiskTypes         []RiskType             `json:"inherited_risk_types,omitempty"`
	PopularityRank             int                    `json:"popularity_rank,omitempty"`
	ResolvesToRefs             []ResolvesToRef        `json:"resolves_to_refs,omitempty"`
	RiskScore                  int                    `json:"risk_score,omitempty"`
	RiskTypes                  []RiskType             `json:"risk_types,omitempty"`
}

type CloudFlareIPResult struct {
	BelongsToRef BelongsToRef `json:"belongs_to_ref,omitempty"`
	IP           string       `json:"ip"`
	RiskScore    int          `json:"risk_score"`
	RiskTypes    []RiskType   `json:"risk_types"`
}

type BelongsToRef struct {
	ID          string `json:"id,omitempty"`
	Value       int    `json:"value,omitempty"`
	Country     string `json:"country,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
}

type AdditionalInformation struct {
	SuspectedMalwareFamily string `json:"suspected_malware_family,omitempty"`
}

type Application struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ContentCategory struct {
	ID              int    `json:"id,omitempty"`
	Name            string `json:"name,omitempty"`
	SuperCategoryID int    `json:"super_category_id,omitempty"`
}

type RiskType struct {
	ID              int    `json:"id,omitempty"`
	Name            string `json:"name,omitempty"`
	SuperCategoryID int    `json:"super_category_id,omitempty"`
}

type ResolvesToRef struct {
	ID    string `json:"id,omitempty"`
	Value string `json:"value,omitempty"`
}

func CloudflareGetCategoryNames(categories []ContentCategory) string {
	names := []string{}
	for _, cat := range categories {
		names = append(names, cat.Name)
	}
	if len(names) == 0 {
		return "N/A"
	}
	return strings.Join(names, ", ")
}
