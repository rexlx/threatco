package optional

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

const BasicPrompt = `You are a dynamic json-to-html engine. the indicators of compromise provided below come from multiple third party vendors. Your task is to generate a comprehensive HTML report that consolidates all the provided indicators of compromise (IOCs) into a single, well-structured format.
The report should include the following sections:

1. Executive Summary: A brief overview of the key findings and highlights from the provided IOCs.
2. IOC Details: A detailed section for each IOC, including:
   - Type of IOC (e.g., IP address, domain, file hash)
   - Source vendor
   - Description or context provided by the vendor
   - Any relevant timestamps or additional metadata
3. Visualizations: Where applicable, include charts or graphs to illustrate trends or patterns observed in the IOCs.
4. Recommendations: Based on the analysis of the IOCs, provide actionable recommendations for mitigation and response.
---
%v`

type promptType string

const (
	LlmToolsBasicPrompt promptType = BasicPrompt
)

type LlmToolsLlmMClient interface {
	CallPrompt(ctx context.Context, prompt string) (string, error)
}

type LlmConfig struct {
	ModelType string `json:"model_type"`
	ApiKey    string `json:"api_key"`
	Provider  string `json:"provider"`
	Enabled   bool   `json:"enabled"`
	RateLimit int    `json:"rate_limit"`
}

type LlmToolsGeminiModel struct {
	ApiKey string `json:"api_key"`
	Model  string `json:"model"`
}

type LlmToolsPromptRequest struct {
	Mu           *sync.RWMutex `json:"-"`
	Id           string        `json:"id"`
	MatchList    []interface{} `json:"match_list"`
	TransactinID string        `json:"transaction_id"`
}

func (p *LlmToolsPromptRequest) BuildPrompt(ptype promptType) (string, error) {
	out, err := json.Marshal(p.MatchList)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(string(ptype), string(out)), nil
}

func (p *LlmToolsPromptRequest) BuildJSONPrompt(ptype promptType) ([]byte, error) {
	var out struct {
		Prompt string `json:"prompt"`
	}
	prompt, err := p.BuildPrompt(ptype)
	if err != nil {
		return nil, err
	}
	out.Prompt = prompt
	return json.Marshal(out)
}

// --- JSON structure for the Gemini API request ---
type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}
type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text string `json:"text"`
}

// --- JSON structure for parsing the Gemini API response ---
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// CallPrompt sends the provided prompt string to the Gemini API using the native http client.
func (l *LlmToolsGeminiModel) CallPrompt(ctx context.Context, prompt string) (string, error) {
	// 1. Define the API endpoint and model
	// model := "gemini-1.5-flash"
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", l.Model, l.ApiKey)

	// 2. Construct the JSON request body payload
	reqBody := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// 3. Create the HTTP POST request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 4. Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute http request: %w", err)
	}
	defer resp.Body.Close()

	// 5. Read and check the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Gemini API response body:", string(respBody))
		return "", fmt.Errorf("api request failed with status %d: %s", resp.StatusCode, url)
	}

	// 6. Unmarshal the JSON response and extract the text
	var apiResp geminiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response json: %w", err)
	}

	if len(apiResp.Candidates) > 0 && len(apiResp.Candidates[0].Content.Parts) > 0 {
		return apiResp.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("received an empty or invalid response from the API")
}
