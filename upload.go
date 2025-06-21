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

type UploadOperator func(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error

var UploadOperators = map[string]UploadOperator{
	"livery": LiveryHelper,
	"vmray":  VmRayFileSubmissionHelper,
	"misp":   MispFileHelper,
}

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
			// In a real scenario, the file.ID might be updated here from the server response
			// file.ID = strings.TrimSpace(string(respBodyBytes))
			fmt.Printf("LiveryHelper: All chunks uploaded successfully for file '%s' (ID: %s). Server acknowledged with final ID: %s\n", file.FileName, file.ID, file.ID)
		}
	}

	// --- Exponential Backoff Logic for Fetching Results ---
	const (
		initialBackoff = 100 * time.Millisecond // Start with 100ms
		maxBackoff     = 2 * time.Second        // Cap individual sleep at 2 seconds
		totalTimeout   = 20 * time.Second       // Total wait time up to 20 seconds
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
			// Assuming a non-empty response means results are ready
			// In a real application, you might parse the JSON and check a status field.
			resch <- ResponseItem{
				ID:     id,
				Vendor: "livery",
				Data:   resultsRespBodyBytes,
				Time:   time.Now(),
			}
			fmt.Printf("LiveryHelper: Successfully fetched analysis results for FileID '%s'. Response length: %d bytes (took %v total)\n",
				file.ID, len(resultsRespBodyBytes), time.Since(startTime).Round(time.Millisecond))
			resultsFetched = true
			break // Exit loop, results fetched
		} else {
			fmt.Printf("LiveryHelper: Results not yet ready for FileID '%s'. Retrying in %v...\n", file.ID, currentBackoff)
			time.Sleep(currentBackoff) // Wait before next retry

			// Exponentially increase backoff, capping at maxBackoff
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

func VmRayFileSubmissionHelper(resch chan ResponseItem, file UploadHandler, ep Endpoint, id string) error {

	thisUrl := fmt.Sprintf("%s/%s", ep.GetURL(), "rest/sample/submit")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("sample_file", file.FileName)
	if err != nil {
		return fmt.Errorf("failed to create form file for upload: %w", err)
	}
	_, err = io.Copy(part, bytes.NewReader(file.Data))
	if err != nil {
		return fmt.Errorf("failed to copy file data to form file: %w", err)
	}
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}
	request, err := http.NewRequest("POST", thisUrl, body)
	if err != nil {
		return fmt.Errorf("failed to create request for file %s: %w", file.FileName, err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	resp := ep.Do(request)
	if len(resp) == 0 {
		return fmt.Errorf("got a zero length response")
	}
	resch <- ResponseItem{
		ID:     id,
		Vendor: "vmray",
		Data:   resp,
		Time:   time.Now(),
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
	// UploadResponse.Status = info
	// uploadHanlder.WriteToDisk(fmt.Sprintf("./static/%s", filename))
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
