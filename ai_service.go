// ai_service.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// Classification types for requests
type RequestCategory string

const (
	CategoryAnalytics RequestCategory = "analytics"
	CategoryAdmin     RequestCategory = "admin"
	CategoryReport    RequestCategory = "report"
	CategoryStandard  RequestCategory = "standard"
	CategoryUnknown   RequestCategory = "unknown"
)

// Risk levels for anomaly detection
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// AI service for request classification and anomaly detection
type AIService struct {
	openAIKey  string
	redisCache *redis.Client
}

// Create a new AI service
func NewAIService(openAIKey string, redisCache *redis.Client) *AIService {
	return &AIService{
		openAIKey:  openAIKey,
		redisCache: redisCache,
	}
}

// Request details for OpenAI API
type OpenAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Response from OpenAI API
type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Classification response
type ClassificationResult struct {
	Category     RequestCategory `json:"category"`
	RiskLevel    RiskLevel       `json:"risk_level"`
	Reason       string          `json:"reason"`
	BlockRequest bool            `json:"block_request"`
}

// Check Redis cache for a similar request
func (s *AIService) checkCache(ctx context.Context, requestBody string) (*ClassificationResult, bool) {
	// Create a cache key from the request body
	// In a production setting, you might want to use a hash function
	key := fmt.Sprintf("ai:classification:%s", requestBody)
	
	// Try to get the classification from cache
	val, err := s.redisCache.Get(ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist in cache
		return nil, false
	} else if err != nil {
		// Redis error
		log.Printf("Redis error checking cache: %v", err)
		return nil, false
	}

	// Cache hit
	var result ClassificationResult
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		log.Printf("Error unmarshaling cached result: %v", err)
		return nil, false
	}
	
	return &result, true
}

// Store classification in Redis cache
func (s *AIService) storeInCache(ctx context.Context, requestBody string, result *ClassificationResult) {
	// Create a cache key
	key := fmt.Sprintf("ai:classification:%s", requestBody)
	
	// Serialize the classification result
	val, err := json.Marshal(result)
	if err != nil {
		log.Printf("Error marshaling result for cache: %v", err)
		return
	}
	
	// Store in Redis with a 30-minute expiration
	if err := s.redisCache.Set(ctx, key, val, 30*time.Minute).Err(); err != nil {
		log.Printf("Redis error storing in cache: %v", err)
	}
}

// Extract important info from request for classification
func (s *AIService) extractRequestInfo(r *http.Request, body []byte) string {
	// Build a string with the key information from the request
	// This will be sent to the AI for classification
	
	var info strings.Builder
	
	// Add request method and path
	info.WriteString(fmt.Sprintf("Method: %s\n", r.Method))
	info.WriteString(fmt.Sprintf("Path: %s\n", r.URL.Path))
	
	// Add query parameters
	if len(r.URL.Query()) > 0 {
		info.WriteString("Query Parameters:\n")
		for key, values := range r.URL.Query() {
			info.WriteString(fmt.Sprintf("  %s: %s\n", key, strings.Join(values, ", ")))
		}
	}
	
	// Add relevant headers
	relevantHeaders := []string{"Content-Type", "Accept", "User-Agent"}
	info.WriteString("Headers:\n")
	for _, header := range relevantHeaders {
		if value := r.Header.Get(header); value != "" {
			info.WriteString(fmt.Sprintf("  %s: %s\n", header, value))
		}
	}
	
	// Add body if it exists and isn't too large
	if len(body) > 0 {
		// Limit body size to avoid huge requests to OpenAI
		maxBodySize := 500
		bodyStr := string(body)
		if len(bodyStr) > maxBodySize {
			bodyStr = bodyStr[:maxBodySize] + "... [truncated]"
		}
		info.WriteString(fmt.Sprintf("Body: %s\n", bodyStr))
	}
	
	return info.String()
}

// Use local/simple classification when OpenAI is not available
func (s *AIService) localClassify(r *http.Request) *ClassificationResult {
	path := strings.ToLower(r.URL.Path)
	method := r.Method
	
	// Simple rule-based classification
	var category RequestCategory
	var riskLevel RiskLevel
	var reason string
	blockRequest := false
	
	// Check for admin operations
	if strings.Contains(path, "admin") || strings.Contains(path, "config") || strings.Contains(path, "settings") {
		category = CategoryAdmin
		riskLevel = RiskMedium
		reason = "Administrative operation detected in path"
	} else if strings.Contains(path, "report") || strings.Contains(path, "export") {
		category = CategoryReport
		riskLevel = RiskLow
		reason = "Reporting operation detected in path"
	} else if strings.Contains(path, "analytics") || strings.Contains(path, "metrics") || strings.Contains(path, "stats") {
		category = CategoryAnalytics
		riskLevel = RiskLow
		reason = "Analytics operation detected in path"
	} else {
		category = CategoryStandard
		riskLevel = RiskLow
		reason = "Standard API request"
	}
	
	// Check for potentially risky operations
	if method == "DELETE" || strings.Contains(path, "delete") || strings.Contains(path, "remove") {
		riskLevel = RiskHigh
		reason += ". Delete operation detected"
	} else if method == "PUT" || method == "PATCH" || (method == "POST" && (strings.Contains(path, "update") || strings.Contains(path, "edit"))) {
		if riskLevel == RiskLow {
			riskLevel = RiskMedium
		}
		reason += ". Update operation detected"
	}
	
	return &ClassificationResult{
		Category:     category,
		RiskLevel:    riskLevel,
		Reason:       reason,
		BlockRequest: blockRequest,
	}
}

// Call OpenAI API to classify the request
func (s *AIService) classifyRequest(ctx context.Context, requestInfo string) (*ClassificationResult, error) {
	// Skip if no API key
	if s.openAIKey == "" {
		log.Println("No OpenAI API key provided, using local classification")
		return nil, fmt.Errorf("no OpenAI API key")
	}
	
	// Prepare the request to OpenAI
	apiURL := "https://api.openai.com/v1/chat/completions"
	
	// Create the prompt for OpenAI
	prompt := `You are an API Gateway security and classification system. Analyze the following API request and:
1. Classify it into one of these categories: "analytics", "admin", "report", "standard", or "unknown"
2. Assess the risk level as: "low", "medium", or "high"
3. Provide a brief reason for your classification and risk assessment
4. Determine if the request should be blocked (true/false)

Here is the request:
%s

Respond with a JSON object in this exact format:
{
  "category": "[category]",
  "risk_level": "[risk_level]",
  "reason": "[reason]",
  "block_request": true/false
}
`
	
	// Format the prompt with the request information
	formattedPrompt := fmt.Sprintf(prompt, requestInfo)
	
	// Create the OpenAI request
	openAIReq := OpenAIRequest{
		Model: "gpt-3.5-turbo",  // Using a simpler model for classification
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are an API security analyzer that returns only valid JSON.",
			},
			{
				Role:    "user",
				Content: formattedPrompt,
			},
		},
	}
	
	// Serialize the request to JSON
	reqBody, err := json.Marshal(openAIReq)
	if err != nil {
		return nil, fmt.Errorf("error marshaling OpenAI request: %v", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("error creating OpenAI request: %v", err)
	}
	
	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.openAIKey))
	
	// Send request to OpenAI
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling OpenAI API: %v", err)
	}
	defer resp.Body.Close()
	
	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading OpenAI response: %v", err)
	}
	
	// Check for successful response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error: %d - %s", resp.StatusCode, respBody)
	}
	
	// Parse the response
	var openAIResp OpenAIResponse
	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		return nil, fmt.Errorf("error unmarshaling OpenAI response: %v", err)
	}
	
	// Check if we have any choices
	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in OpenAI response")
	}
	
	// Get the content of the response
	content := openAIResp.Choices[0].Message.Content
	
	// Parse the JSON response
	var result ClassificationResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("error parsing classification result: %v", err)
	}
	
	return &result, nil
}

// Full method to classify and detect anomalies in a request
func (s *AIService) AnalyzeRequest(ctx context.Context, r *http.Request, body []byte) (*ClassificationResult, error) {
	// Extract the relevant information from the request
	requestInfo := s.extractRequestInfo(r, body)
	
	// Check if we have a cached result for a similar request
	if cachedResult, found := s.checkCache(ctx, requestInfo); found {
		log.Println("Using cached classification")
		return cachedResult, nil
	}
	
	// Call OpenAI to classify the request
	result, err := s.classifyRequest(ctx, requestInfo)
	if err != nil {
		log.Printf("Error using OpenAI classification: %v. Using local classification.", err)
		// Fallback to local classification on error
		result = s.localClassify(r)
	}
	
	// Store the result in cache for future similar requests
	s.storeInCache(ctx, requestInfo, result)
	
	return result, nil
}