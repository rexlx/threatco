package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Constants for polling configuration.
const (
	DefaultPollingTimeout  = 15 * time.Minute
	DefaultPollingInterval = 30 * time.Second
)

// VmRayFileSubmissionResponse represents the initial response after submitting a file.
type VmRayFileSubmissionResponse struct {
	Data struct {
		Errors      []any             `json:"errors"`
		Submissions []VmRaySubmission `json:"submissions"`
	} `json:"data"`
}

// VmRaySubmission represents a single submission entry.
type VmRaySubmission struct {
	SubmissionID int           `json:"submission_id"`
	WebifURL     string        `json:"submission_webif_url"`
	Samples      []VmRaySample `json:"samples"`
}

// VmRaySample represents a file sample analyzed within a submission.
type VmRaySample struct {
	SampleID int             `json:"sample_id"`
	Analyses []VmRayAnalysis `json:"analyses"`
}

// VmRayAnalysis represents a single analysis run on a sample.
type VmRayAnalysis struct {
	AnalysisID int    `json:"analysis_id"`
	Status     string `json:"job_status"` // e.g., "in_work", "finished", "in_queue"
}

type UploadOperator func(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error

var UploadOperators = map[string]UploadOperator{
	"livery": LiveryHelper,
	"vmray":  VmRayFileSubmissionHelper,
	"misp":   MispFileHelper,
}

// getVmRaySubmission fetches the current status of a VMRay submission.
func getVmRaySubmission(ep Endpoint, submissionID int) (*VmRaySubmission, error) {
	// The endpoint to get submission status.
	statusURL := fmt.Sprintf("%s/rest/submission/%d", ep.GetURL(), submissionID)
	req, err := http.NewRequest("GET", statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create submission status request: %w", err)
	}

	// The ep.Do method is assumed to handle authentication (e.g., adding the API key header).
	respBytes := ep.Do(req)
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("received empty response when fetching status for submission %d", submissionID)
	}

	var submissionResponse struct {
		Data VmRaySubmission `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &submissionResponse); err != nil {
		return nil, fmt.Errorf("failed to decode submission status response: %w", err)
	}

	return &submissionResponse.Data, nil
}

// pollVmRayForCompletion blocks until the analysis is complete.
func pollVmRayForCompletion(ep Endpoint, submissionID int) (*VmRaySubmission, error) {
	timeoutChan := time.After(DefaultPollingTimeout)
	ticker := time.NewTicker(DefaultPollingInterval)
	defer ticker.Stop()

	fmt.Printf("Polling VMRay for submission %d every %s...\n", submissionID, DefaultPollingInterval)

	for {
		select {
		case <-timeoutChan:
			return nil, fmt.Errorf("timed out waiting for VMRay submission %d", submissionID)
		case <-ticker.C:
			submission, err := getVmRaySubmission(ep, submissionID)
			if err != nil {
				fmt.Printf("Error getting VMRay submission status: %v. Retrying...\n", err)
				continue
			}

			if submission == nil || len(submission.Samples) == 0 || len(submission.Samples[0].Analyses) == 0 {
				fmt.Printf("Analysis for submission %d not yet started. Retrying...\n", submissionID)
				continue
			}

			allAnalysesComplete := true
			for _, sample := range submission.Samples {
				for _, analysis := range sample.Analyses {
					fmt.Printf(" > Status for analysis %d: %s\n", analysis.AnalysisID, analysis.Status)
					if analysis.Status == "in_work" || analysis.Status == "in_queue" {
						allAnalysesComplete = false
						break
					}
				}
				if !allAnalysesComplete {
					break
				}
			}

			if allAnalysesComplete {
				fmt.Printf("All analyses for submission %d are complete.\n", submissionID)
				return submission, nil
			}
		}
	}
}

// VmRayFileSubmissionHelper submits a file and polls until analysis is complete.
func VmRayFileSubmissionHelper(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error {
	// 1. Submit the file for analysis
	submitURL := fmt.Sprintf("%s/%s", ep.GetURL(), "rest/sample/submit")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("sample_file", file.FileName)
	_, _ = io.Copy(part, bytes.NewReader(file.Data))
	writer.Close()

	request, err := http.NewRequest("POST", submitURL, body)
	if err != nil {
		return fmt.Errorf("failed to create VMRay submission request: %w", err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())

	// The ep.Do method is assumed to handle authentication.
	initialRespBytes := ep.Do(request)
	if len(initialRespBytes) == 0 {
		return fmt.Errorf("got a zero length response from VMRay on file submission")
	}
	if len(initialRespBytes) == 0 {
		return fmt.Errorf("got a zero length response")
	}
	resch <- ResponseItem{
		ID:     id,
		Vendor: "vmray",
		Data:   initialRespBytes,
		Time:   time.Now(),
	}
	// 2. Parse the initial response to get the submission ID
	var submissionResp VmRayFileSubmissionResponse
	if err := json.Unmarshal(initialRespBytes, &submissionResp); err != nil {
		return fmt.Errorf("failed to unmarshal VMRay submission response: %w. Response was: %s", err, string(initialRespBytes))
	}
	if len(submissionResp.Data.Submissions) == 0 {
		return fmt.Errorf("VMRay submission response contained no submissions")
	}
	submissionID := submissionResp.Data.Submissions[0].SubmissionID
	fmt.Printf("Successfully submitted file to VMRay. Submission ID: %d...waiting\n", submissionID)

	// 3. Poll for the final analysis result
	finalSubmission, err := pollVmRayForCompletion(ep, submissionID)
	if err != nil {
		return fmt.Errorf("failed while polling for VMRay analysis completion: %w", err)
	}

	// 4. Send the final, completed submission data to the channel
	finalData, err := json.Marshal(finalSubmission)
	if err != nil {
		return fmt.Errorf("failed to marshal final VMRay submission data: %w", err)
	}

	resch <- ResponseItem{
		ID:     id,
		Vendor: "vmray",
		Data:   finalData,
		Time:   time.Now(),
	}
	return nil
}

// LiveryHelper and MispFileHelper remain unchanged...
func LiveryHelper(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error {
	const chunkSize = 1024 * 1024
	totalChunks := (len(file.Data) + chunkSize - 1) / chunkSize

	uploadUrl := fmt.Sprintf("%s/upload-chunk", ep.GetURL())

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(file.Data) {
			end = len(file.Data)
		}
		part := file.Data[start:end]

		isLastChunk := i == totalChunks-1

		req, err := http.NewRequest("POST", uploadUrl, bytes.NewBuffer(part))
		if err != nil {
			return fmt.Errorf("failed to create upload request for chunk %d: %w", i, err)
		}

		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-File-ID", file.ID)
		req.Header.Set("X-Filename", file.FileName)
		req.Header.Set("X-Last-Chunk", strconv.FormatBool(isLastChunk))
		req.ContentLength = int64(len(part))

		respBodyBytes := ep.Do(req)
		if len(respBodyBytes) == 0 {
			return fmt.Errorf("received an empty or error response from server for chunk %d of file '%s'", i+1, file.FileName)
		}
		fmt.Printf("LiveryHelper: Uploaded chunk %d/%d for file '%s'. Server response: %s\n", i+1, totalChunks, file.FileName, strings.TrimSpace(string(respBodyBytes)))

		if isLastChunk {
			fmt.Printf("LiveryHelper: All chunks uploaded successfully for file '%s' (ID: %s). Server acknowledged with final ID: %s\n", file.FileName, file.ID, file.ID)
		}
	}

	const (
		initialBackoff = 100 * time.Millisecond
		maxBackoff     = 2 * time.Second
		totalTimeout   = 20 * time.Second
	)

	currentBackoff := initialBackoff
	startTime := time.Now()
	resultsFetched := false

	resultsReqBody := ResultsRequest{FileID: file.ID}
	jsonBody, err := json.Marshal(resultsReqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal results request body for file ID '%s': %w", file.ID, err)
	}

	resultsUrl := fmt.Sprintf("%s/results", ep.GetURL())

	for time.Since(startTime) < totalTimeout {
		fmt.Printf("LiveryHelper: Attempting to fetch analysis results for FileID '%s' from %s (attempt after %v wait, total elapsed: %v)\n",
			file.ID, resultsUrl, currentBackoff, time.Since(startTime).Round(time.Millisecond))

		resultsReq, err := http.NewRequest("POST", resultsUrl, bytes.NewBuffer(jsonBody))
		if err != nil {
			return fmt.Errorf("failed to create results fetch request for file ID '%s': %w", file.ID, err)
		}
		resultsReq.Header.Set("Content-Type", "application/json")
		resultsReq.ContentLength = int64(len(jsonBody))

		resultsRespBodyBytes := ep.Do(resultsReq)
		responseStr := strings.TrimSpace(string(resultsRespBodyBytes))

		if len(resultsRespBodyBytes) > 0 && responseStr != "No results found for the provided FileID" {
			resch <- ResponseItem{
				ID:     id,
				Vendor: "livery",
				Data:   resultsRespBodyBytes,
				Time:   time.Now(),
			}
			fmt.Printf("LiveryHelper: Successfully fetched analysis results for FileID '%s'. Response length: %d bytes (took %v total)\n",
				file.ID, len(resultsRespBodyBytes), time.Since(startTime).Round(time.Millisecond))
			resultsFetched = true
			break
		} else {
			fmt.Printf("LiveryHelper: Results not yet ready for FileID '%s'. Retrying in %v...\n", file.ID, currentBackoff)
			time.Sleep(currentBackoff)

			currentBackoff *= 2
			if currentBackoff > maxBackoff {
				currentBackoff = maxBackoff
			}
		}
	}

	if !resultsFetched {
		return fmt.Errorf("LiveryHelper: Timed out after %v waiting for results for file ID '%s'", totalTimeout, file.ID)
	}

	return nil
}

func MispFileHelper(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error {
	hasher := sha256.New()
	_, err := hasher.Write(file.Data)
	if err != nil {
		return fmt.Errorf("failed to compute hash for file %s: %w", file.FileName, err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	uid := uuid.New().String()
	info := fmt.Sprintf("%v: File %s uploaded with hash %s", uid, file.FileName, hash)
	file.ID = uid
	fmt.Println(info)
	thisUrl := fmt.Sprintf("%s/", ep.GetURL())
	var output GenericOut
	output.Type = "sha256"
	output.Value = hash
	out, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output for file %s: %w", file.FileName, err)
	}
	request, err := http.NewRequest("POST", thisUrl, bytes.NewBuffer(out))
	if err != nil {
		return fmt.Errorf("failed to create request for file %s: %w", file.FileName, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	res := ep.Do(request)
	if len(res) == 0 {
		return fmt.Errorf("received an empty response for file %s", file.FileName)
	}
	resch <- ResponseItem{
		ID:     id,
		Vendor: "misp",
		Data:   res,
		Time:   time.Now(),
	}
	return nil
}
