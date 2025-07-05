package vendors

import (
	"encoding/json"
	"time"
)

type URLIOScanRequest struct {
	URL        string   `json:"url"`
	Visibility string   `json:"visibility"`
	Tags       []string `json:"tags,omitempty"`
	Country    string   `json:"country,omitempty"`
}

type URLIOScanResponse struct {
	UUID       string `json:"uuid"`
	URL        string `json:"url"`
	Country    string `json:"country"`
	Visibility string `json:"visibility"`
}

type URLIOScanResultResponse struct {
	Data      URLIOScanData     `json:"data"`
	Stats     URLIOScanStats    `json:"stats"`
	Meta      URLIOScanMeta     `json:"meta"`
	Task      URLIOScanTask     `json:"task"`
	Page      URLIOScanPage     `json:"page"`
	Lists     URLIOScanLists    `json:"lists"`
	Verdicts  URLIOScanVerdicts `json:"verdicts"`
	Submitter URLIOSubmitter    `json:"submitter"`
}

type URLIOScanData struct {
	Requests []URLIORequestResponse `json:"requests,omitempty"`
	Cookies  []URLIOCookie          `json:"cookies,omitempty"`
	Console  []URLIOConsoleMessage  `json:"console,omitempty"`
	Links    []URLIOLink            `json:"links,omitempty"`
	Timing   URLIOTiming            `json:"timing"`
	Globals  []URLIOGlobal          `json:"globals,omitempty"`
}

type URLIORequestResponse struct {
	Request       URLIORequestDetails  `json:"request"`
	Response      URLIOResponseDetails `json:"response"`
	InitiatorInfo *URLIOInitiatorInfo  `json:"initiatorInfo,omitempty"`
}

type URLIORequestDetails struct {
	RequestID            string           `json:"requestId"`
	LoaderID             string           `json:"loaderId"`
	DocumentURL          string           `json:"documentURL"`
	Request              URLIOHTTPRequest `json:"request"`
	Timestamp            float64          `json:"timestamp"`
	WallTime             float64          `json:"wallTime"`
	Initiator            URLIOInitiator   `json:"initiator"`
	RedirectHasExtraInfo bool             `json:"redirectHasExtraInfo"`
	Type                 string           `json:"type"`
	FrameIDS             string           `json:"frameId"`
	HasUserGesture       bool             `json:"hasUserGesture"`
	PrimaryRequest       bool             `json:"primaryRequest,omitempty"`
}

type URLIOHTTPRequest struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers"`
	MixedContentType string            `json:"mixedContentType"`
	InitialPriority  string            `json:"initialPriority"`
	ReferrerPolicy   string            `json:"referrerPolicy"`
	IsSameSite       bool              `json:"isSameSite"`
	IsLinkPreload    bool              `json:"isLinkPreload,omitempty"`
}

type URLIOInitiator struct {
	Type         string `json:"type"`
	URL          string `json:"url,omitempty"`
	LineNumber   int    `json:"lineNumber,omitempty"`
	ColumnNumber int    `json:"columnNumber,omitempty"`
}

type URLIOResponseDetails struct {
	EncodedDataLength int               `json:"encodedDataLength"`
	DataLength        int               `json:"dataLength"`
	RequestID         string            `json:"requestId"`
	Type              string            `json:"type"`
	Response          URLIOHTTPResponse `json:"response"`
	HasExtraInfo      bool              `json:"hasExtraInfo"`
	Hash              string            `json:"hash"`
	Size              int               `json:"size"`
	ASN               URLIOASNInfo      `json:"asn"`
	GeoIP             URLIOGeoIPInfo    `json:"geoip"`
	RDNS              URLIORDNSInfo     `json:"rdns"`
}

type URLIOHTTPResponse struct {
	URL                    string                `json:"url"`
	Status                 int                   `json:"status"`
	StatusText             string                `json:"statusText"`
	Headers                map[string]string     `json:"headers"`
	MimeType               string                `json:"mimeType"`
	RemoteIPAddress        string                `json:"remoteIPAddress"`
	RemotePort             int                   `json:"remotePort"`
	EncodedDataLength      int                   `json:"encodedDataLength"`
	Timing                 URLIOTimingDetails    `json:"timing"`
	ResponseTime           float64               `json:"responseTime"`
	Protocol               string                `json:"protocol"`
	AlternateProtocolUsage string                `json:"alternateProtocolUsage"`
	SecurityState          string                `json:"securityState"`
	SecurityDetails        URLIOSecurityDetails  `json:"securityDetails"`
	SecurityHeaders        []URLIOSecurityHeader `json:"securityHeaders,omitempty"`
}

type URLIOTimingDetails struct {
	RequestTime              float64 `json:"requestTime"`
	ProxyStart               int     `json:"proxyStart"`
	ProxyEnd                 int     `json:"proxyEnd"`
	DNSStart                 float64 `json:"dnsStart"`
	DNSEnd                   float64 `json:"dnsEnd"`
	ConnectStart             float64 `json:"connectStart"`
	ConnectEnd               float64 `json:"connectEnd"`
	SSLStart                 float64 `json:"sslStart"`
	SSLEnd                   float64 `json:"sslEnd"`
	WorkerStart              int     `json:"workerStart"`
	WorkerReady              int     `json:"workerReady"`
	WorkerFetchStart         int     `json:"workerFetchStart"`
	WorkerRespondWithSettled int     `json:"workerRespondWithSettled"`
	SendStart                float64 `json:"sendStart"`
	SendEnd                  float64 `json:"sendEnd"`
	PushStart                int     `json:"pushStart"`
	PushEnd                  int     `json:"pushEnd"`
	ReceiveHeadersStart      float64 `json:"receiveHeadersStart"`
	ReceiveHeadersEnd        float64 `json:"receiveHeadersEnd"`
}

type URLIOSecurityDetails struct {
	Protocol                          string        `json:"protocol"`
	KeyExchange                       string        `json:"keyExchange"`
	KeyExchangeGroup                  string        `json:"keyExchangeGroup"`
	Cipher                            string        `json:"cipher"`
	CertificateID                     int           `json:"certificateId"`
	SubjectName                       string        `json:"subjectName"`
	SANList                           []string      `json:"sanList,omitempty"`
	Issuer                            string        `json:"issuer"`
	ValidFrom                         int           `json:"validFrom"`
	ValidTo                           int           `json:"validTo"`
	SignedCertificateTimestampList    []interface{} `json:"signedCertificateTimestampList,omitempty"`
	CertificateTransparencyCompliance string        `json:"certificateTransparencyCompliance"`
	ServerSignatureAlgorithm          int           `json:"serverSignatureAlgorithm"`
	EncryptedClientHello              bool          `json:"encryptedClientHello"`
}

type URLIOSecurityHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type URLIOASNInfo struct {
	IP          string `json:"ip"`
	ASN         string `json:"asn"`
	Country     string `json:"country"`
	Registrar   string `json:"registrar"`
	Date        string `json:"date"`
	Description string `json:"description"`
	Route       string `json:"route"`
	Name        string `json:"name"`
}

type URLIOGeoIPInfo struct {
	Country     string    `json:"country"`
	Region      string    `json:"region,omitempty"`
	Timezone    string    `json:"timezone"`
	City        string    `json:"city,omitempty"`
	LL          []float64 `json:"ll,omitempty"`
	CountryName string    `json:"country_name"`
	Metro       int       `json:"metro"`
}

type URLIORDNSInfo struct {
	IP  string `json:"ip"`
	PTR string `json:"ptr"`
}

type URLIOInitiatorInfo struct {
	URL  string `json:"url"`
	Host string `json:"host"`
	Type string `json:"type"`
}

type URLIOCookie struct {
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Domain       string  `json:"domain"`
	Path         string  `json:"path"`
	Expires      float64 `json:"expires"`
	Size         int     `json:"size"`
	HTTPOnly     bool    `json:"httpOnly"`
	Secure       bool    `json:"secure"`
	Session      bool    `json:"session"`
	SameSite     string  `json:"sameSite,omitempty"`
	Priority     string  `json:"priority"`
	SameParty    bool    `json:"sameParty"`
	SourceScheme string  `json:"sourceScheme"`
	SourcePort   int     `json:"sourcePort"`
}

type URLIOConsoleMessage struct {
	Message URLIOMessage `json:"message"`
}

type URLIOMessage struct {
	Source    string  `json:"source"`
	Level     string  `json:"level"`
	Text      string  `json:"text"`
	Timestamp float64 `json:"timestamp"`
	URL       string  `json:"url"`
}

type URLIOLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

type URLIOTiming struct {
	BeginNavigation      string `json:"beginNavigation"`
	FrameStartedLoading  string `json:"frameStartedLoading"`
	FrameNavigated       string `json:"frameNavigated"`
	DomContentEventFired string `json:"domContentEventFired"`
	FrameStoppedLoading  string `json:"frameStoppedLoading"`
}

type URLIOGlobal struct {
	Prop string `json:"prop"`
	Type string `json:"type"`
}

type URLIOScanStats struct {
	ResourceStats    []URLIOResourceStat  `json:"resourceStats,omitempty"`
	ProtocolStats    []URLIOProtocolStat  `json:"protocolStats,omitempty"`
	TLSStats         []URLIOTLSStat       `json:"tlsStats,omitempty"`
	ServerStats      []URLIOServerStat    `json:"serverStats,omitempty"`
	DomainStats      []URLIODomainStat    `json:"domainStats,omitempty"`
	RegDomainStats   []URLIORegDomainStat `json:"regDomainStats,omitempty"`
	SecureRequests   int                  `json:"secureRequests"`
	SecurePercentage int                  `json:"securePercentage"`
	IPv6Percentage   int                  `json:"IPv6Percentage"`
	UniqCountries    int                  `json:"uniqCountries"`
	TotalLinks       int                  `json:"totalLinks"`
	Malicious        int                  `json:"malicious"`
	AdBlocked        int                  `json:"adBlocked"`
	IPStats          []URLIOIPStat        `json:"ipStats,omitempty"`
}

type URLIOResourceStat struct {
	Count       int      `json:"count"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	Latency     int      `json:"latency"`
	Countries   []string `json:"countries,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Type        string   `json:"type"`
	Compression string   `json:"compression"`
	Percentage  int      `json:"percentage"`
}

type URLIOProtocolStat struct {
	Count         int                    `json:"count"`
	Size          int                    `json:"size"`
	EncodedSize   int                    `json:"encodedSize"`
	IPs           []string               `json:"ips,omitempty"`
	Countries     []string               `json:"countries,omitempty"`
	SecurityState map[string]interface{} `json:"securityState,omitempty"`
	Protocol      string                 `json:"protocol"`
}

type URLIOTLSStat struct {
	Count         int            `json:"count"`
	Size          int            `json:"size"`
	EncodedSize   int            `json:"encodedSize"`
	IPs           []string       `json:"ips,omitempty"`
	Countries     []string       `json:"countries,omitempty"`
	Protocols     map[string]int `json:"protocols,omitempty"`
	SecurityState string         `json:"securityState"`
}

type URLIOServerStat struct {
	Count       int      `json:"count"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	IPs         []string `json:"ips,omitempty"`
	Countries   []string `json:"countries,omitempty"`
	Server      string   `json:"server"`
}

type URLIODomainStat struct {
	Count       int      `json:"count"`
	IPs         []string `json:"ips,omitempty"`
	Domain      string   `json:"domain"`
	Size        int      `json:"size"`
	EncodedSize int      `json:"encodedSize"`
	Countries   []string `json:"countries,omitempty"`
	Index       int      `json:"index"`
	Initiators  []string `json:"initiators,omitempty"`
	Redirects   int      `json:"redirects"`
}

type URLIORegDomainStat struct {
	Count       int              `json:"count"`
	IPs         []string         `json:"ips,omitempty"`
	RegDomain   string           `json:"regDomain"`
	Size        int              `json:"size"`
	EncodedSize int              `json:"encodedSize"`
	Countries   []string         `json:"countries,omitempty"`
	Index       int              `json:"index"`
	SubDomains  []URLIOSubDomain `json:"subDomains,omitempty"`
	Redirects   int              `json:"redirects"`
}

type URLIOSubDomain struct {
	Domain  string `json:"domain"`
	Country string `json:"country"`
}

type URLIOIPStat struct {
	Requests    int                    `json:"requests"`
	Domains     []string               `json:"domains,omitempty"`
	IP          string                 `json:"ip"`
	ASN         URLIOASNInfo           `json:"asn"`
	DNS         map[string]interface{} `json:"dns,omitempty"`
	GeoIP       URLIOGeoIPInfo         `json:"geoip"`
	Size        int                    `json:"size"`
	EncodedSize int                    `json:"encodedSize"`
	Countries   []string               `json:"countries,omitempty"`
	Index       int                    `json:"index"`
	IPv6        bool                   `json:"ipv6"`
	Redirects   int                    `json:"redirects"`
	Count       interface{}            `json:"count,omitempty"`
	RDNS        *URLIORDNSInfo         `json:"rdns,omitempty"`
}

type URLIOScanMeta struct {
	Processors URLIOProcessors `json:"processors"`
}

type URLIOProcessors struct {
	Umbrella URLIOUmbrellaProcessor `json:"umbrella"`
	GeoIP    URLIOGeoIPProcessor    `json:"geoip"`
	RDNS     URLIORDNSProcessor     `json:"rdns"`
	ASN      URLIOASNProcessor      `json:"asn"`
	Wappa    URLIOWappaProcessor    `json:"wappa"`
}

type URLIOUmbrellaProcessor struct {
	Data []URLIOUmbrellaData `json:"data,omitempty"`
}

type URLIOUmbrellaData struct {
	Hostname string `json:"hostname"`
	Rank     int    `json:"rank"`
}

type URLIOGeoIPProcessor struct {
	Data []URLIOGeoIPData `json:"data,omitempty"`
}

type URLIOGeoIPData struct {
	IP    string         `json:"ip"`
	GeoIP URLIOGeoIPInfo `json:"geoip"`
}

type URLIORDNSProcessor struct {
	Data []URLIORDNSInfo `json:"data,omitempty"`
}

type URLIOASNProcessor struct {
	Data []URLIOASNInfo `json:"data,omitempty"`
}

type URLIOWappaProcessor struct {
	Data []URLIOWappaData `json:"data,omitempty"`
}

type URLIOWappaData struct {
	Confidence      []URLIOConfidence `json:"confidence,omitempty"`
	ConfidenceTotal int               `json:"confidenceTotal"`
	App             string            `json:"app"`
	Icon            string            `json:"icon"`
	Website         string            `json:"website"`
	Categories      []URLIOCategory   `json:"categories,omitempty"`
}

type URLIOConfidence struct {
	Confidence int    `json:"confidence"`
	Pattern    string `json:"pattern"`
}

type URLIOCategory struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

type URLIOScanTask struct {
	UUID          string        `json:"uuid"`
	Time          string        `json:"time"`
	URL           string        `json:"url"`
	Visibility    string        `json:"visibility"`
	Method        string        `json:"method"`
	Source        string        `json:"source"`
	Tags          []interface{} `json:"tags,omitempty"`
	ReportURL     string        `json:"reportURL"`
	ScreenshotURL string        `json:"screenshotURL"`
	DomURL        string        `json:"domURL"`
}

type URLIOScanPage struct {
	URL     string `json:"url"`
	Domain  string `json:"domain"`
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	Server  string `json:"server"`
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	ASNName string `json:"asnname"`
}

type URLIOScanLists struct {
	IPs          []string           `json:"ips,omitempty"`
	Countries    []string           `json:"countries,omitempty"`
	ASNs         []string           `json:"asns,omitempty"`
	Domains      []string           `json:"domains,omitempty"`
	Servers      []string           `json:"servers,omitempty"`
	URLs         []string           `json:"urls,omitempty"`
	LinkDomains  []string           `json:"linkDomains,omitempty"`
	Certificates []URLIOCertificate `json:"certificates,omitempty"`
	Hashes       []string           `json:"hashes,omitempty"`
}

type URLIOCertificate struct {
	SubjectName string `json:"subjectName"`
	Issuer      string `json:"issuer"`
	ValidFrom   int    `json:"validFrom"`
	ValidTo     int    `json:"validTo"`
}

type URLIOScanVerdicts struct {
	Overall   URLIOVerdict          `json:"overall"`
	URLScan   URLIOVerdict          `json:"urlscan"`
	Engines   URLIOEnginesVerdict   `json:"engines"`
	Community URLIOCommunityVerdict `json:"community"`
}

type URLIOVerdict struct {
	Score       int           `json:"score"`
	Categories  []interface{} `json:"categories,omitempty"`
	Brands      []interface{} `json:"brands,omitempty"`
	Tags        []interface{} `json:"tags,omitempty"`
	Malicious   bool          `json:"malicious"`
	HasVerdicts bool          `json:"hasVerdicts"`
}

type URLIOEnginesVerdict struct {
	Score             int           `json:"score"`
	Categories        []interface{} `json:"categories,omitempty"`
	EnginesTotal      int           `json:"enginesTotal"`
	MaliciousTotal    int           `json:"maliciousTotal"`
	BenignTotal       int           `json:"benignTotal"`
	MaliciousVerdicts []interface{} `json:"maliciousVerdicts,omitempty"`
	BenignVerdicts    []interface{} `json:"benignVerdicts,omitempty"`
	Malicious         bool          `json:"malicious"`
	HasVerdicts       bool          `json:"hasVerdicts"`
}

type URLIOCommunityVerdict struct {
	Score          int           `json:"score"`
	Categories     []interface{} `json:"categories,omitempty"`
	Brands         []interface{} `json:"brands,omitempty"`
	VotesTotal     int           `json:"votesTotal"`
	VotesMalicious int           `json:"votesMalicious"`
	VotesBenign    int           `json:"votesBenign"`
	Malicious      bool          `json:"malicious"`
	HasVerdicts    bool          `json:"hasVerdicts"`
}

type URLIOSubmitter struct {
	Country string `json:"country"`
}

func UnmarshalAPIResponse(data []byte) (URLIOScanResultResponse, error) {
	var r URLIOScanResultResponse
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *URLIOScanResultResponse) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

type URLScanSearchResponse struct {
	Results []URLScanResult `json:"results,omitempty"`
	Total   int             `json:"total,omitempty"`
	Took    int             `json:"took,omitempty"`
	HasMore bool            `json:"has_more,omitempty"`
}

type URLScanResult struct {
	Verdicts   *URLScanSearchVerdicts  `json:"verdicts,omitempty"`
	Submitter  *URLScanSearchSubmitter `json:"submitter,omitempty"`
	DOM        *URLScanSearchDOM       `json:"dom,omitempty"`
	Frames     *URLScanSearchFrames    `json:"frames,omitempty"`
	Canonical  *URLScanSearchCanonical `json:"canonical,omitempty"`
	Task       *URLScanSearchTask      `json:"task,omitempty"`
	Stats      *URLScanSearchStats     `json:"stats,omitempty"`
	Scanner    *URLScanSearchScanner   `json:"scanner,omitempty"`
	Links      *URLScanSearchLinks     `json:"links,omitempty"`
	Page       *URLScanSearchPage      `json:"page,omitempty"`
	Text       *URLScanSearchText      `json:"text,omitempty"`
	ID         string                  `json:"_id,omitempty"`
	Score      interface{}             `json:"_score,omitempty"`
	Sort       []interface{}           `json:"sort,omitempty"`
	Result     string                  `json:"result,omitempty"`
	Screenshot string                  `json:"screenshot,omitempty"`
}

type URLScanSearchVerdicts struct {
	Score       int                          `json:"score,omitempty"`
	Malicious   bool                         `json:"malicious,omitempty"`
	URLScan     *URLScanSearchURLScanVerdict `json:"urlscan,omitempty"`
	HasVerdicts bool                         `json:"hasVerdicts,omitempty"`
}

type URLScanSearchURLScanVerdict struct {
	Malicious bool `json:"malicious,omitempty"`
}

type URLScanSearchSubmitter struct {
	Country string `json:"country,omitempty"`
}

type URLScanSearchDOM struct {
	Size int    `json:"size,omitempty"`
	Hash string `json:"hash,omitempty"`
}

type URLScanSearchFrames struct {
	Length int `json:"length,omitempty"`
}

type URLScanSearchCanonical struct {
	Task *URLScanSearchCanonicalURL `json:"task,omitempty"`
	Page *URLScanSearchCanonicalURL `json:"page,omitempty"`
}

type URLScanSearchCanonicalURL struct {
	URL string `json:"url,omitempty"`
}

type URLScanSearchTask struct {
	Visibility string    `json:"visibility,omitempty"`
	Method     string    `json:"method,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	ApexDomain string    `json:"apexDomain,omitempty"`
	Time       time.Time `json:"time,omitempty"`
	UUID       string    `json:"uuid,omitempty"`
	URL        string    `json:"url,omitempty"`
}

type URLScanSearchStats struct {
	UniqIPs           int `json:"uniqIPs,omitempty"`
	UniqCountries     int `json:"uniqCountries,omitempty"`
	DataLength        int `json:"dataLength,omitempty"`
	EncodedDataLength int `json:"encodedDataLength,omitempty"`
	Requests          int `json:"requests,omitempty"`
}

type URLScanSearchScanner struct {
	Country string `json:"country,omitempty"`
}

type URLScanSearchLinks struct {
	Length int `json:"length,omitempty"`
}

type URLScanSearchPage struct {
	Country      string    `json:"country,omitempty"`
	Server       string    `json:"server,omitempty"`
	IP           string    `json:"ip,omitempty"`
	MimeType     string    `json:"mimeType,omitempty"`
	Title        string    `json:"title,omitempty"`
	URL          string    `json:"url,omitempty"`
	TLSValidDays int       `json:"tlsValidDays,omitempty"`
	TLSAgeDays   int       `json:"tlsAgeDays,omitempty"`
	PTR          string    `json:"ptr,omitempty"`
	TLSValidFrom time.Time `json:"tlsValidFrom,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	UmbrellaRank int       `json:"umbrellaRank,omitempty"`
	ApexDomain   string    `json:"apexDomain,omitempty"`
	ASNName      string    `json:"asnname,omitempty"`
	ASN          string    `json:"asn,omitempty"`
	TLSIssuer    string    `json:"tlsIssuer,omitempty"`
	Status       string    `json:"status,omitempty"`
}

type URLScanSearchText struct {
	Size int    `json:"size,omitempty"`
	Hash string `json:"hash,omitempty"`
}
