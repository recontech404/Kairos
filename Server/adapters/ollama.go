package adapters

import (
	"context"
	"fmt"

	"github.com/ollama/ollama/api"
	"github.com/pkoukk/tiktoken-go"
	tiktoken_loader "github.com/pkoukk/tiktoken-go-loader"
)

const BaseSystemPrompt = "You will act as a translator for eBPF tracepoint events for a malicious program. You will provide a detailed one paragraph of the events which I provide and sugguest what the malware is doing and try to estimate what type of malware it is. Stop confirming my requests, instead go straight to answering my exact question. You should not reference the user or yourself in the response or provide a recommendation section."
const headerPrompt = "Function Name Function Arguments"

type LLM struct {
	Client *api.Client
	Tke    *tiktoken.Tiktoken
}

func SetupOllamaAPI() (*api.Client, error) {
	client, err := api.ClientFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("unable to get ollama env: %v", err)
	}
	return client, nil
}

func SetupTokenCounter(encoding string) (*tiktoken.Tiktoken, error) {
	tiktoken.SetBpeLoader(tiktoken_loader.NewOfflineLoader())
	tke, err := tiktoken.GetEncoding(encoding)
	if err != nil {
		return nil, fmt.Errorf("encoding err: %v", err)
	}
	return tke, nil
}

func SendLLMRequest(client api.Client, model string, events []byte, top_k, top_p, temp, repeat_pen float64, ctx_len int, systemPrompt string) ([]byte, error) {
	sysPromptToUse := BaseSystemPrompt
	if systemPrompt != "" {
		sysPromptToUse = systemPrompt
	}

	req := &api.GenerateRequest{
		Model:  model,
		Prompt: fmt.Sprintf("%s\n%s", headerPrompt, string(events)),
		Stream: new(bool),
		System: sysPromptToUse,
		Options: map[string]interface{}{
			"top_k":          top_k,
			"top_p":          top_p,
			"temperature":    temp,
			"repeat_penalty": repeat_pen,
			"num_ctx":        ctx_len,
			//"num_predict":    128,
		},
	}

	var llmResponse string

	ctx := context.Background() //request could take a while
	respFunc := func(resp api.GenerateResponse) error {
		llmResponse = resp.Response
		return nil
	}

	err := client.Generate(ctx, req, respFunc)
	if err != nil {
		return nil, fmt.Errorf("unable to generate LLM response: %v", err)
	}

	return []byte(llmResponse), nil
}
