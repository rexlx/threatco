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

const LlmToolsBasicPrompt = `You are an intel analyst. Your task is to analyze the indicators of compromise (IOCs) provided in the input and further enrich them and to categorize them by how significant the threat is. There may be duplicate values of different types (urls and domains): %v`

type LlmToolsLlmMClient interface {
	CallPrompt(ctx context.Context, prompt string) (string, error)
}

type LlmToolsGeminiModel struct {
	ApiKey string `json:"api_key"`
}

type LlmToolsPromptRequest struct {
	Mu           *sync.RWMutex `json:"-"`
	Id           string        `json:"id"`
	MatchList    []interface{} `json:"match_list"`
	TransactinID string        `json:"transaction_id"`
}

func (p *LlmToolsPromptRequest) BuildPrompt() (string, error) {
	out, err := json.Marshal(p.MatchList)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(LlmToolsBasicPrompt, string(out)), nil
}

func (p *LlmToolsPromptRequest) BuildJSONPrompt() ([]byte, error) {
	var out struct {
		Prompt string `json:"prompt"`
	}
	prompt, err := p.BuildPrompt()
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
	model := "gemini-1.5-flash"
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, l.ApiKey)

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
		return "", fmt.Errorf("api request failed with status %d: %s", resp.StatusCode, string(respBody))
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
