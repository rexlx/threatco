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

type DomainToolsIrisEnrichResponse struct {
	Response struct {
		LimitExceeded  bool   `json:"limit_exceeded"`
		HasMoreResults bool   `json:"has_more_results"`
		Message        string `json:"message"`
		ResultsCount   int    `json:"results_count"`
		TotalCount     int    `json:"total_count"`
		Results        []struct {
			Domain   string `json:"domain"`
			WhoisURL string `json:"whois_url"`
			Adsense  struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"adsense"`
			Alexa           string `json:"alexa"`
			Active          bool   `json:"active"`
			GoogleAnalytics struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"google_analytics"`
			GA4 []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"ga4"`
			GTMCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"gtm_codes"`
			FBCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"fb_codes"`
			HotjarCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"hotjar_codes"`
			BaiduCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"baidu_codes"`
			YandexCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"yandex_codes"`
			MatomoCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"matomo_codes"`
			StatcounterProjectCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"statcounter_project_codes"`
			StatcounterSecurityCodes []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"statcounter_security_codes"`
			AdminContact struct {
				Name struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"name"`
				Org struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"org"`
				Street struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"street"`
				City struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"city"`
				State struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"state"`
				Postal struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"postal"`
				Country struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"country"`
				Phone struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"phone"`
				Fax struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"fax"`
				Email []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"email"`
			} `json:"admin_contact"`
			BillingContact struct {
				Name struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"name"`
				Org struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"org"`
				Street struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"street"`
				City struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"city"`
				State struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"state"`
				Postal struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"postal"`
				Country struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"country"`
				Phone struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"phone"`
				Fax struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"fax"`
				Email []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"email"`
			} `json:"billing_contact"`
			RegistrantContact struct {
				Name struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"name"`
				Org struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"org"`
				Street struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"street"`
				City struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"city"`
				State struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"state"`
				Postal struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"postal"`
				Country struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"country"`
				Phone struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"phone"`
				Fax struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"fax"`
				Email []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"email"`
			} `json:"registrant_contact"`
			TechnicalContact struct {
				Name struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"name"`
				Org struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"org"`
				Street struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"street"`
				City struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"city"`
				State struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"state"`
				Postal struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"postal"`
				Country struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"country"`
				Phone struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"phone"`
				Fax struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"fax"`
				Email []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"email"`
			} `json:"technical_contact"`
			CreateDate struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"create_date"`
			ExpirationDate struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"expiration_date"`
			EmailDomain []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"email_domain"`
			SoaEmail []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"soa_email"`
			SslEmail []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"ssl_email"`
			AdditionalWhoisEmail []struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"additional_whois_email"`
			IP []struct {
				Address struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"address"`
				ASN []struct {
					Value int `json:"value"`
					Count int `json:"count"`
				} `json:"asn"`
				CountryCode struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"country_code"`
				ISP struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"isp"`
			} `json:"ip"`
			MX []struct {
				Host struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"host"`
				Domain struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"domain"`
				IP []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"ip"`
				Priority int `json:"priority"`
			} `json:"mx"`
			NameServer []struct {
				Host struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"host"`
				Domain struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"domain"`
				IP []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"ip"`
			} `json:"name_server"`
			DomainRisk struct {
				RiskScore  int `json:"risk_score"`
				Components []struct {
					Name      string   `json:"name"`
					RiskScore int      `json:"risk_score"`
					Threats   []string `json:"threats"`
					Evidence  []string `json:"evidence"`
				} `json:"components"`
			} `json:"domain_risk"`
			Redirect struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"redirect"`
			RedirectDomain struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"redirect_domain"`
			RegistrantName struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"registrant_name"`
			RegistrantOrg struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"registrant_org"`
			Registrar struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"registrar"`
			RegistrarStatus []string `json:"registrar_status"`
			SPFInfo         string   `json:"spf_info"`
			SSLInfo         []struct {
				Hash struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"hash"`
				Subject struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"subject"`
				Organization struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"organization"`
				Email    []string `json:"email"`
				AltNames []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"alt_names"`
				Sources struct {
					Active int `json:"active"`
				} `json:"sources"`
				CommonName struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"common_name"`
				IssuerCommonName struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"issuer_common_name"`
				NotAfter struct {
					Value int `json:"value"`
					Count int `json:"count"`
				} `json:"not_after"`
				NotBefore struct {
					Value int `json:"value"`
					Count int `json:"count"`
				} `json:"not_before"`
				Duration struct {
					Value int `json:"value"`
					Count int `json:"count"`
				} `json:"duration"`
			} `json:"ssl_info"`
			TLD                  string `json:"tld"`
			WebsiteResponse      int    `json:"website_response"`
			DataUpdatedTimestamp string `json:"data_updated_timestamp"`
			WebsiteTitle         struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"website_title"`
			ServerType struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"server_type"`
			FirstSeen struct {
				Value string `json:"value"`
				Count int    `json:"count"`
			} `json:"first_seen"`
			Tags []struct {
				Label    string `json:"label"`
				Scope    string `json:"scope"`
				TaggedAt string `json:"tagged_at"`
			} `json:"tags"`
		} `json:"results"`
		MissingDomains []string `json:"missing_domains"`
	} `json:"response"`
}
