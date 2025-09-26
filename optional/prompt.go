package optional

import (
	"context"
	"encoding/json"
	"fmt"
)

const BasicPrompt = `You are an intel analyst. Your task is to analyze the indicators of compromise (IOCs) provided in the input anf further enrich them if possible
and to categorize them by how significant the threat is. %v`

type LLMClient interface {
	CallPrompt(ctx context.Context, prompt string) (string, error)
}

type PromptRequest struct {
	Id           string        `json:"id"`
	MatchList    []interface{} `json:"match_list"`
	TransactinID string        `json:"transaction_id"`
}

func (p *PromptRequest) BuildPrompt() (string, error) {
	out, err := json.Marshal(p.MatchList)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(BasicPrompt, string(out)), nil
}
