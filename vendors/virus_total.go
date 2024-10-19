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

type VirusTotalAttributes struct {
	Whois                    string                        `json:"whois"`
	LastAnalysisStats        VirusTotalLastAnalysisStats   `json:"last_analysis_stats"`
	Continent                string                        `json:"continent"`
	TotalVotes               VirusTotalTotalVotes          `json:"total_votes"`
	AsOwner                  string                        `json:"as_owner"`
	Country                  string                        `json:"country"`
	LastAnalysisResults      VirusTotalLastAnalysisResults `json:"last_analysis_results"`
	Reputation               int                           `json:"reputation"`
	LastAnalysisDate         int                           `json:"last_analysis_date"`
	WhoisDate                int                           `json:"whois_date"`
	Network                  string                        `json:"network"`
	LastModificationDate     int                           `json:"last_modification_date"`
	Tags                     []string                      `json:"tags"`
	RegionalInternetRegistry string                        `json:"regional_internet_registry"`
	ASN                      int                           `json:"asn"`
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
