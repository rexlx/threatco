package vendors

type VirusTotalResponse struct {
	Data VirusTotalData `json:"data"`
}

type VirusTotalData struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"`
	Links      VirusTotalLinks      `json:"links"`
	Attributes VirusTotalAttributes `json:"attributes"`
}

type VirusTotalLinks struct {
	Self string `json:"self"`
}

type GTIAssessment struct {
	Verdict     string `json:"verdict,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
}

type PopularThreatCategory struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type PopularThreatName struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type PopularThreatClassification struct {
	SuggestedThreatLabel  string                  `json:"suggested_threat_label,omitempty"`
	PopularThreatCategory []PopularThreatCategory `json:"popular_threat_category,omitempty"`
	PopularThreatName     []PopularThreatName     `json:"popular_threat_name,omitempty"`
}

type GTIThreatActor struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type GTIMandiantAssociation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type VirusTotalAttributes struct {
	Whois                    string                        `json:"whois,omitempty"`
	LastAnalysisStats        VirusTotalLastAnalysisStats   `json:"last_analysis_stats"`
	Continent                string                        `json:"continent,omitempty"`
	TotalVotes               VirusTotalTotalVotes          `json:"total_votes"`
	AsOwner                  string                        `json:"as_owner,omitempty"`
	Country                  string                        `json:"country,omitempty"`
	LastAnalysisResults      VirusTotalLastAnalysisResults `json:"last_analysis_results"`
	Reputation               int                           `json:"reputation"`
	LastAnalysisDate         int                           `json:"last_analysis_date,omitempty"`
	WhoisDate                int                           `json:"whois_date,omitempty"`
	Network                  string                        `json:"network,omitempty"`
	LastModificationDate     int                           `json:"last_modification_date,omitempty"`
	Tags                     []string                      `json:"tags,omitempty"`
	RegionalInternetRegistry string                        `json:"regional_internet_registry,omitempty"`
	ASN                      int                           `json:"asn,omitempty"`
	Categories               map[string]string             `json:"categories,omitempty"`
	WhoisRegistrar           string                        `json:"whois_registrar,omitempty"`
	WhoisCountry             string                        `json:"whois_country,omitempty"`
	LastDNSRecordsDate       int                           `json:"last_dns_records_date,omitempty"`
	LastDNSRecords           []DNSRecord                   `json:"last_dns_records,omitempty"`

	// Google Threat Intelligence (GTI) & Mandiant additions
	GTIAssessment               *GTIAssessment               `json:"gti_assessment,omitempty"`
	PopularThreatClassification *PopularThreatClassification `json:"popular_threat_classification,omitempty"`
	MandiantAssociations        []GTIMandiantAssociation     `json:"mandiant_associations,omitempty"`
	ThreatActors                []GTIThreatActor             `json:"threat_actors,omitempty"`
	MandiantRiskScore           int                          `json:"mandiant_risk_score,omitempty"`
}

type DNSRecord struct {
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

type VirusTotalLastAnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
	Timeout    int `json:"timeout"`
}

type VirusTotalTotalVotes struct {
	Harmless  int `json:"harmless"`
	Malicious int `json:"malicious"`
}

type VirusTotalEngine struct {
	Method    string `json:"method"`
	Engine    string `json:"engine_name"`
	Category  string `json:"category"`
	Result    string `json:"result"`
	Verdict   string `json:"verdict"`
	Reference string `json:"reference"`
}

type VirusTotalLastAnalysisResults struct {
	Acronis                    VirusTotalEngine `json:"Acronis"`
	ZeroXSI_f33d               VirusTotalEngine `json:"0xSI_f33d"`
	Abusix                     VirusTotalEngine `json:"Abusix"`
	ADMINUSLabs                VirusTotalEngine `json:"ADMINUSLabs"`
	Axur                       VirusTotalEngine `json:"Axur"`
	CriminalIP                 VirusTotalEngine `json:"Criminal IP"`
	AILabsMONITORAPP           VirusTotalEngine `json:"AILabs (MONITORAPP)"`
	AlienVault                 VirusTotalEngine `json:"AlienVault"`
	AlphaMountainai            VirusTotalEngine `json:"alphaMountain.ai"`
	AlphaSOC                   VirusTotalEngine `json:"AlphaSOC"`
	AntiyAVL                   VirusTotalEngine `json:"Antiy-AVL"`
	ArcSightThreatIntelligence VirusTotalEngine `json:"ArcSight Threat Intelligence"`
	AutoShun                   VirusTotalEngine `json:"AutoShun"`
	Benkowcc                   VirusTotalEngine `json:"benkow.cc"`
	BforeAiPreCrime            VirusTotalEngine `json:"Bfore.Ai PreCrime"`
	BitDefender                VirusTotalEngine `json:"BitDefender"`
	Bkav                       VirusTotalEngine `json:"Bkav"`
	Blueliv                    VirusTotalEngine `json:"Blueliv"`
	Certego                    VirusTotalEngine `json:"Certego"`
	ChongLuaDao                VirusTotalEngine `json:"Chong Lua Dao"`
	CINSArmy                   VirusTotalEngine `json:"CINS Army"`
	Cluster25                  VirusTotalEngine `json:"Cluster25"`
	CRDF                       VirusTotalEngine `json:"CRDF"`
	CSISSecurityGroup          VirusTotalEngine `json:"CSIS Security Group"`
	SnortIPSampleList          VirusTotalEngine `json:"Snort IP sample list"`
	CMCThreatIntelligence      VirusTotalEngine `json:"CMC Threat Intelligence"`
	Cyan                       VirusTotalEngine `json:"Cyan"`
	Cyble                      VirusTotalEngine `json:"Cyble"`
	CyRadar                    VirusTotalEngine `json:"CyRadar"`
	DNS8                       VirusTotalEngine `json:"DNS8"`
	DrWeb                      VirusTotalEngine `json:"Dr.Web"`
	Ermes                      VirusTotalEngine `json:"Ermes"`
	ESET                       VirusTotalEngine `json:"ESET"`
	ESTsecurity                VirusTotalEngine `json:"ESTsecurity"`
	EmergingThreats            VirusTotalEngine `json:"EmergingThreats"`
	Emsisoft                   VirusTotalEngine `json:"Emsisoft"`
	ForcepointThreatSeeker     VirusTotalEngine `json:"Forcepoint ThreatSeeker"`
	Fortinet                   VirusTotalEngine `json:"Fortinet"`
	GData                      VirusTotalEngine `json:"G-Data"`
	GCPAbuseIntelligence       VirusTotalEngine `json:"GCP Abuse Intelligence"`
}
