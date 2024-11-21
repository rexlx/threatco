package vendors

type IndicatorResponse struct {
	Indicators []Indicator `json:"indicators"`
}

type Indicator struct {
	AssociatedHashes       []AssociatedHash        `json:"associated_hashes"`
	AttributedAssociations []AttributedAssociation `json:"attributed_associations"`
	Actors                 []Actor                 `json:"actors"`
	Malware                []Malware               `json:"malware"`
	FirstSeen              string                  `json:"first_seen"`
	ID                     string                  `json:"id"`
	IsExclusive            bool                    `json:"is_exclusive"`
	IsPublishable          bool                    `json:"is_publishable"`
	LastSeen               string                  `json:"last_seen"`
	LastUpdated            string                  `json:"last_updated"`
	Misp                   Misp                    `json:"misp"`
	Mscore                 int                     `json:"mscore"`
	Reports                []Report                `json:"reports"`
	Campaigns              []Campaign              `json:"campaigns"`
	Sources                []Source                `json:"sources"`
	Type                   string                  `json:"type"`
	Value                  string                  `json:"value"`
	Category               []string                `json:"category"`
	VerdictSimple          VerdictSimple           `json:"verdict_simple"`
	Attribution            []string                `json:"attribution"`
	ThreatRating           ThreatRating            `json:"threat_rating"`
}

type AssociatedHash struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AttributedAssociation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type Actor struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	AttributionScope string `json:"attribution_scope"`
}

type Malware struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Roles string `json:"roles"`
}

type Report struct {
	ReportID      string `json:"report_id"`
	Type          string `json:"type"`
	Title         string `json:"title"`
	PublishedDate string `json:"published_date"`
}

type Campaign struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

type Source struct {
	Category   []string `json:"category"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	Osint      bool     `json:"osint"`
	SourceName string   `json:"source_name"`
}

type VerdictSimple struct {
	Sources       []string `json:"sources"`
	Timestamp     string   `json:"timestamp"`
	Verdict       string   `json:"verdict"`
	VerdictSource string   `json:"verdict_source"`
}

type ThreatRating struct {
	ConfidenceLevel string   `json:"confidence_level"`
	ConfidenceScore int      `json:"confidence_score"`
	SeverityLevel   string   `json:"severity_level"`
	SeverityReason  []string `json:"severity_reason"`
	ThreatScore     int      `json:"threat_score"`
}

type Misp struct {
	Akamai                               bool `json:"akamai"`
	Alexa                                bool `json:"alexa"`
	Alexa1M                              bool `json:"alexa_1M"`
	Amazon                               bool `json:"amazon-aws"`
	Apple                                bool `json:"apple"`
	AutomatedMalwareAnalysis             bool `json:"automated-malware-analysis"`
	BankWebsite                          bool `json:"bank-website"`
	Cisco1M                              bool `json:"cisco_1M"`
	CiscoTop1000                         bool `json:"cisco_top1000"`
	CiscoTop10k                          bool `json:"cisco_top10k"`
	CiscoTop20k                          bool `json:"cisco_top20k"`
	CiscoTop5k                           bool `json:"cisco_top5k"`
	Cloudflare                           bool `json:"cloudflare"`
	CommonContactEmails                  bool `json:"common-contact-emails"`
	CommonIOCFalsePositive               bool `json:"common-ioc-False-positive"`
	Covid                                bool `json:"covid"`
	Covid19CyberThreatCoalitionWhitelist bool `json:"covid-19-cyber-threat-coalition-whitelist"`
	Covid19KrassiWhitelist               bool `json:"covid-19-krassi-whitelist"`
	CRLHostname                          bool `json:"crl-hostname"`
	CRLIP                                bool `json:"crl-ip"`
	DAX30                                bool `json:"dax30"`
	DisposableEmail                      bool `json:"disposable-email"`
	DynamicDNS                           bool `json:"dynamic-dns"`
	EicarCom                             bool `json:"eicar.com"`
	EmptyHashes                          bool `json:"empty-hashes"`
	Fastly                               bool `json:"fastly"`
	Google                               bool `json:"google"`
	GoogleGCP                            bool `json:"google-gcp"`
	GoogleGmailSendingIPs                bool `json:"google-gmail-sending-ips"`
	Googlebot                            bool `json:"googlebot"`
	IPv6LinkLocal                        bool `json:"ipv6-linklocal"`
	MajesticMillion                      bool `json:"majestic_million"`
	MajesticMillion1M                    bool `json:"majestic_million_1M"`
	Microsoft                            bool `json:"microsoft"`
	MicrosoftAttackSimulator             bool `json:"microsoft-attack-simulator"`
	MicrosoftAzure                       bool `json:"microsoft-azure"`
	MicrosoftAzureChina                  bool `json:"microsoft-azure-china"`
	MicrosoftAzureGermany                bool `json:"microsoft-azure-germany"`
	MicrosoftAzureUSGov                  bool `json:"microsoft-azure-us-gov"`
	MicrosoftOffice365                   bool `json:"microsoft-office365"`
	MicrosoftOffice365CN                 bool `json:"microsoft-office365-cn"`
	MicrosoftOffice365IP                 bool `json:"microsoft-office365-ip"`
	MicrosoftWin10ConnectionEndpoints    bool `json:"microsoft-win10-connection-endpoints"`
	MozTop500                            bool `json:"moz-top500"`
	MozillaCA                            bool `json:"mozilla-CA"`
	MozillaIntermediateCA                bool `json:"mozilla-IntermediateCA"`
	Multicast                            bool `json:"multicast"`
	NiocFilehash                         bool `json:"nioc-filehash"`
	OvhCluster                           bool `json:"ovh-cluster"`
	PhoneNumbers                         bool `json:"phone_numbers"`
	PublicDNSHostname                    bool `json:"public-dns-hostname"`
	PublicDNSV4                          bool `json:"public-dns-v4"`
	PublicDNSV6                          bool `json:"public-dns-v6"`
	RFC1918                              bool `json:"rfc1918"`
	RFC3849                              bool `json:"rfc3849"`
	RFC5735                              bool `json:"rfc5735"`
	RFC6598                              bool `json:"rfc6598"`
	RFC6761                              bool `json:"rfc6761"`
	SecondLevelTLDs                      bool `json:"second-level-tlds"`
	SecurityProviderBlogpost             bool `json:"security-provider-blogpost"`
	Sinkholes                            bool `json:"sinkholes"`
	SMTPReceivingIPs                     bool `json:"smtp-receiving-ips"`
	SMTPSendingIPs                       bool `json:"smtp-sending-ips"`
	Stackpath                            bool `json:"stackpath"`
	TIFalsepositives                     bool `json:"ti-Falsepositives"`
	TLDs                                 bool `json:"tlds"`
	Tranco                               bool `json:"tranco"`
	Tranco10k                            bool `json:"tranco10k"`
	UniversityDomains                    bool `json:"university_domains"`
	URLShortener                         bool `json:"url-shortener"`
	VPNIPv4                              bool `json:"vpn-ipv4"`
	VPNIPv6                              bool `json:"vpn-ipv6"`
	WhatsMyIP                            bool `json:"whats-my-ip"`
	Wikimedia                            bool `json:"wikimedia"`
}
