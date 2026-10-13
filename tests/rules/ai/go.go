package main

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"os"
	"os/exec"

	"github.com/anthropics/anthropic-sdk-go"
	openai "github.com/sashabaranov/go-openai"
	"github.com/tmc/langchaingo/llms"
)

func sqlHandler(w http.ResponseWriter, r *http.Request, client *openai.Client, db *sql.DB) {
	q := r.URL.Query().Get("q")
	resp, _ := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model:    openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: q}},
	})
	query := resp.Choices[0].Message.Content
	// ruleid: llm05-llm-output-to-sql
	db.Query(query)
	// ok: llm05-llm-output-to-sql
	db.Query("SELECT name FROM products WHERE category = $1", query)
}

func execHandler(w http.ResponseWriter, r *http.Request, llm llms.Model) {
	q := r.FormValue("q")
	cmd, _ := llms.GenerateFromSinglePrompt(context.Background(), llm, q)
	// ruleid: llm05-llm-output-to-code-exec
	exec.Command("sh", "-c", cmd).Run()
	// ok: llm05-llm-output-to-code-exec
	exec.Command("uptime").Run()
}

func fetchHandler(w http.ResponseWriter, r *http.Request, client anthropic.Client) {
	q := r.URL.Query().Get("q")
	msg, _ := client.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeOpus4_5,
		MaxTokens: 256,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(q))},
	})
	url := msg.Content[0].Text
	// ruleid: llm05-llm-output-to-request
	http.Get(url)
	// ruleid: llm05-llm-output-to-filesystem
	os.ReadFile(url)
	// ruleid: llm05-llm-output-to-html
	_ = template.HTML(url)
	// ok: llm05-llm-output-to-html
	_ = template.HTML("<b>hola</b>")
}

func systemHandler(w http.ResponseWriter, r *http.Request, client *openai.Client) {
	persona := r.URL.Query().Get("persona")
	client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{
			// ruleid: llm01-untrusted-input-in-system-prompt
			{Role: openai.ChatMessageRoleSystem, Content: "Actúa como " + persona},
			// ok: llm01-untrusted-input-in-system-prompt
			{Role: openai.ChatMessageRoleSystem, Content: "Eres un asistente."},
		},
	})
}

const systemPrompt = "Eres el asistente interno. La contraseña de la base de datos es Pr0duccion2026."

func secretHandler(client *openai.Client) {
	client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Messages: []openai.ChatCompletionMessage{
			// ruleid: llm07-secret-in-system-prompt
			{Role: openai.ChatMessageRoleSystem, Content: "La clave de la API es sk-abcdefghijklmnop1234"},
		},
	})
}
