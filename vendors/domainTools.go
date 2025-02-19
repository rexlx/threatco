package vendors

type DomainProfileResponse struct {
	Response struct {
		Registrant struct {
			Name       string `json:"name"`
			Domains    int    `json:"domains"`
			ProductURL string `json:"product_url"`
		} `json:"registrant"`
		Server struct {
			IPAddress    string `json:"ip_address"`
			OtherDomains int    `json:"other_domains"`
			ProductURL   string `json:"product_url"`
		} `json:"server"`
		Registration struct {
			Created   string   `json:"created"`
			Expires   string   `json:"expires"`
			Updated   string   `json:"updated"`
			Registrar string   `json:"registrar"`
			Statuses  []string `json:"statuses"`
		} `json:"registration"`
		NameServers []struct {
			Server     string `json:"server"`
			ProductURL string `json:"product_url"`
		} `json:"name_servers"`
		History struct {
			Registrar struct {
				EarliestEvent string `json:"earliest_event"`
				Events        int    `json:"events"`
				ProductURL    string `json:"product_url"`
			} `json:"registrar"`
			NameServer struct {
				Events          int    `json:"events"`
				TimespanInYears int    `json:"timespan_in_years"`
				ProductURL      string `json:"product_url"`
			} `json:"name_server"`
			IPAddress struct {
				Events          int    `json:"events"`
				TimespanInYears int    `json:"timespan_in_years"`
				ProductURL      string `json:"product_url"`
			} `json:"ip_address"`
			Whois struct {
				Records       int    `json:"records"`
				EarliestEvent string `json:"earliest_event"`
				ProductURL    string `json:"product_url"`
			} `json:"whois"`
		} `json:"history"`
		SEO struct {
			Score      string `json:"score"`
			ProductURL string `json:"product_url"`
		} `json:"seo"`
		WebsiteData struct {
			ResponseCode string   `json:"response_code"`
			Title        string   `json:"title"`
			Server       string   `json:"server"`
			Meta         []string `json:"meta"`
			ProductURL   string   `json:"product_url"`
		} `json:"website_data"`
	} `json:"response"`
}
