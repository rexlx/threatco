package vendors

type VmRayAnalysisResponse struct {
}
type VmRayFileSubmissionResponse struct {
	// Data contains the main content of the response.
	Data struct {
		// Errors that occurred during the submission process.
		Errors []any `json:"errors"`

		// Submissions that were created.
		Submissions []VmRaySubmission `json:"submissions"`
	} `json:"data"`
}

// VmRaySubmission represents a single submission entry in the VMRay API response.
type VmRaySubmission struct {
	// Created timestamp of the submission.
	Created string `json:"submission_created"`

	// Filename of the submitted file.
	Filename string `json:"submission_filename"`

	// ID of the submission.
	SubmissionID int `json:"submission_id"`

	// URL to view the submission in the VMRay Analyzer UI.
	WebifURL string `json:"submission_webif_url"`

	// User-defined tags for the submission.
	Tags []string `json:"submission_tags"`

	// Samples associated with this submission.
	Samples []VmRaySample `json:"samples"`
}

// VmRaySample represents a file sample analyzed within a submission.
type VmRaySample struct {
	// Created timestamp of the sample analysis.
	Created string `json:"sample_created"`

	// Filename of the sample.
	Filename string `json:"sample_filename"`

	// ID of the sample.
	SampleID int `json:"sample_id"`

	// MD5 hash of the sample.
	MD5 string `json:"sample_md5hash"`

	// SHA1 hash of the sample.
	SHA1 string `json:"sample_sha1hash"`

	// SHA256 hash of the sample.
	SHA256 string `json:"sample_sha256hash"`

	// Type of the sample (e.g., "PE32").
	Type string `json:"sample_type"`

	// URL to view the sample analysis in the VMRay Analyzer UI.
	WebifURL string `json:"sample_webif_url"`

	// Analyses performed on this sample.
	Analyses []VmRayAnalysis `json:"analyses"`
}

// VmRayAnalysis represents a single analysis run on a sample.
type VmRayAnalysis struct {
	// Created timestamp of the analysis.
	Created string `json:"analysis_created"`

	// ID of the analysis.
	AnalysisID int `json:"analysis_id"`

	// Job ID associated with the analysis.
	JobID int `json:"job_id"`

	// Status of the analysis (e.g., "in_work", "finished").
	Status string `json:"job_status"`

	// VM name used for the analysis.
	VMName string `json:"vm_name"`

	// URL to view the analysis report in the VMRay Analyzer UI.
	WebifURL string `json:"analysis_webif_url"`
}

type VMRaySubmissionResponse struct {
	Data struct {
		SubmissionID            int    `json:"submission_id"`
		SubmissionFinished      bool   `json:"submission_finished"`
		SubmissionHasError      bool   `json:"submission_has_error"`
		SubmissionSampleVerdict string `json:"submission_sample_verdict"`
	} `json:"data"`
}
