// main.go - Consolidated file with all components
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Constants for buffer size
const maxBodySize = 1024 * 1024 // 1MB

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

// Configuration struct for our gateway
type Config struct {
	Port            string
	BackendServices map[string]string
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	OpenAIKey       string
}

// API Gateway struct
type APIGateway struct {
	config     Config
	router     *mux.Router
	redisCache *redis.Client
	aiService  *AIService
}

// Classification response
type ClassificationResult struct {
	Category     RequestCategory `json:"category"`
	RiskLevel    RiskLevel       `json:"risk_level"`
	Reason       string          `json:"reason"`
	BlockRequest bool            `json:"block_request"`
}

//
// AI SERVICE IMPLEMENTATION
//

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

//
// API GATEWAY IMPLEMENTATION
//

// Initialize API Gateway
func NewAPIGateway(config Config) (*APIGateway, error) {
	// Initialize redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Failed to connect to Redis: %v", err)
		log.Printf("Continuing without full Redis functionality...")
	} else {
		log.Println("Connected to Redis successfully")
	}

	// Initialize AI service
	aiService := NewAIService(config.OpenAIKey, rdb)

	// Setup router
	router := mux.NewRouter()

	gateway := &APIGateway{
		config:     config,
		router:     router,
		redisCache: rdb,
		aiService:  aiService,
	}

	// Setup routes
	gateway.setupRoutes()

	return gateway, nil
}

// Set up routes for the API Gateway
func (g *APIGateway) setupRoutes() {
	// Health check
	g.router.HandleFunc("/health", g.healthCheckHandler).Methods("GET")

	// Dashboard
	g.router.HandleFunc("/dashboard", g.dashboardHandler).Methods("GET")

	// API Endpoints
	apiRouter := g.router.PathPrefix("/api").Subrouter()
	
	// Apply middleware to all API routes - order matters!
	apiRouter.Use(g.loggingMiddleware)  // 1. Log all requests
	apiRouter.Use(g.authenticationMiddleware) // 2. Authenticate
	apiRouter.Use(g.aiMiddleware)       // 3. AI classification and anomaly detection
	apiRouter.Use(g.rateLimitMiddleware)// 4. Apply rate limits

	// Set up proxies for backend services
	for path, target := range g.config.BackendServices {
		targetURL, err := url.Parse(target)
		if err != nil {
			log.Fatalf("Invalid backend service URL: %v", err)
		}

		prefix := fmt.Sprintf("/api/%s", path)
		apiRouter.PathPrefix(prefix).Handler(
			http.StripPrefix(
				prefix,
				g.createReverseProxy(targetURL),
			),
		)
		log.Printf("Route registered: %s -> %s", prefix, target)
	}

	// Mock API endpoint for testing when no backend services are available
	apiRouter.PathPrefix("/mock").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get AI classification from context
		category := "unknown"
		if cat, ok := r.Context().Value("ai_category").(RequestCategory); ok {
			category = string(cat)
		}
		
		riskLevel := "unknown"
		if risk, ok := r.Context().Value("ai_risk_level").(RiskLevel); ok {
			riskLevel = string(risk)
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"service": "Mock API Service",
			"path": r.URL.Path,
			"method": r.Method,
			"timestamp": time.Now().Format(time.RFC3339),
			"message": "This is a mock response for testing the AI-powered API Gateway",
			"ai_classification": map[string]string{
				"category": category,
				"risk_level": riskLevel,
			},
		})
	})

	// Catch-all route
	g.router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
}

// Health check handler
func (g *APIGateway) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"status": true})
}

// Dashboard handler
func (g *APIGateway) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Get request counts from Redis
	totalCount, _ := g.redisCache.Get(ctx, "stats:total").Int64()
	
	// Get category counts
	categoryCounters := map[string]int64{}
	for _, category := range []string{
		string(CategoryAdmin),
		string(CategoryAnalytics),
		string(CategoryReport),
		string(CategoryStandard),
		string(CategoryUnknown),
	} {
		key := fmt.Sprintf("stats:category:%s", category)
		count, _ := g.redisCache.Get(ctx, key).Int64()
		categoryCounters[category] = count
	}
	
	// Get risk level counts
	riskCounters := map[string]int64{}
	for _, risk := range []string{
		string(RiskLow),
		string(RiskMedium),
		string(RiskHigh),
	} {
		key := fmt.Sprintf("stats:risk:%s", risk)
		count, _ := g.redisCache.Get(ctx, key).Int64()
		riskCounters[risk] = count
	}
	
	// Get block counts
	blockCount, _ := g.redisCache.Get(ctx, "stats:blocked").Int64()
	
	// Create a response with the metrics
	response := map[string]interface{}{
		"status": "operational",
		"total_requests": totalCount,
		"blocked_requests": blockCount,
		"category_distribution": categoryCounters,
		"risk_distribution": riskCounters,
		"gateway_info": "AI-Powered API Gateway",
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	// Return the dashboard data as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding dashboard response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Logging middleware
func (g *APIGateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()

		log.Printf(
			"Request: ID=%s Method=%s Path=%s RemoteAddr=%s UserAgent=%s",
			requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent(),
		)

		// Create a custom response writer to capture status code
		lrw := newLoggingResponseWriter(w)
		
		// Call the next handler
		next.ServeHTTP(lrw, r)

		log.Printf(
			"Response: ID=%s StatusCode=%d ContentLength=%d",
			requestID, lrw.statusCode, lrw.contentLength,
		)
		
		// Increment request counter in Redis
		g.redisCache.Incr(r.Context(), "stats:total")
	})
}

// Custom response writer that captures status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK, 0}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := lrw.ResponseWriter.Write(b)
	lrw.contentLength += size
	return size, err
}

// Authentication middleware
func (g *APIGateway) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// For demo purposes, we'll allow requests without auth
			log.Printf("Warning: Request without Authorization header")
			next.ServeHTTP(w, r)
			return
		}

		// Usually we'd validate the token here (e.g., JWT)
		// This is a simplified implementation
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized - Invalid token format", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		// In a real implementation, validate the token against your auth service
		// For now, we'll accept any non-empty token
		if token == "" {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}
		
		// Add user information to the request context
		// In a real app, you'd extract user info from the validated token
		userCtx := context.WithValue(r.Context(), "user_id", "user-123")
		r = r.WithContext(userCtx)
		
		next.ServeHTTP(w, r)
	})
}

// AI middleware to classify and analyze requests
func (g *APIGateway) aiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip AI analysis for health checks and dashboard
		if r.URL.Path == "/health" || r.URL.Path == "/dashboard" {
			next.ServeHTTP(w, r)
			return
		}

		// Read the request body for analysis
		var bodyBytes []byte
		var err error

		if r.Body != nil {
			// Limit the body size to avoid memory issues
			bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
			if err != nil {
				log.Printf("Error reading request body: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			// Restore the body for the next handlers
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Start a timeout context for the AI analysis
		aiCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Call the AI service to analyze the request
		result, err := g.aiService.AnalyzeRequest(aiCtx, r, bodyBytes)
		if err != nil {
			log.Printf("Error analyzing request: %v", err)
			// We'll continue processing the request even if AI analysis fails
			result = &ClassificationResult{
				Category:     CategoryUnknown,
				RiskLevel:    RiskLow,
				Reason:       "Error during analysis: " + err.Error(),
				BlockRequest: false,
			}
		}

		// Log the classification result
		log.Printf(
			"AI Classification: Path=%s Category=%s RiskLevel=%s Block=%v Reason=%s",
			r.URL.Path, result.Category, result.RiskLevel, result.BlockRequest, result.Reason,
		)

		// Update AI stats in Redis
		g.updateAIStats(r.Context(), result)

		// Check if we should block this request
		if result.BlockRequest {
			log.Printf("Blocking request: %s %s (Reason: %s)", r.Method, r.URL.Path, result.Reason)
			http.Error(w, "Request blocked: "+result.Reason, http.StatusForbidden)
			return
		}

		// Add the classification information to the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "ai_category", result.Category)
		ctx = context.WithValue(ctx, "ai_risk_level", result.RiskLevel)
		r = r.WithContext(ctx)

		// Add classification headers for backend services
		r.Header.Set("X-Request-Category", string(result.Category))
		r.Header.Set("X-Risk-Level", string(result.RiskLevel))

		// Process the request based on category
		switch result.Category {
		case CategoryAdmin:
			// For high-risk admin requests, we might want additional verification
			if result.RiskLevel == RiskHigh {
				log.Printf("High-risk admin request detected: %s %s", r.Method, r.URL.Path)
				// In a production system, you might implement additional checks here
			}
			
		case CategoryAnalytics:
			// Analytics requests might be routed to specialized backends
			// or have different rate limiting policies
			
		case CategoryReport:
			// Report generation requests might have longer timeouts
			// or be queued differently
			
		case CategoryStandard:
			// Standard requests proceed normally
			
		case CategoryUnknown:
			// Unknown category requests might need more monitoring
			if result.RiskLevel != RiskLow {
				log.Printf("Unknown category with risk level %s: %s %s", 
					result.RiskLevel, r.Method, r.URL.Path)
			}
		}
		
		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// Update AI stats in Redis
func (g *APIGateway) updateAIStats(ctx context.Context, result *ClassificationResult) {
	// Increment category counter
	g.redisCache.Incr(ctx, fmt.Sprintf("stats:category:%s", result.Category))
	
	// Increment risk level counter
	g.redisCache.Incr(ctx, fmt.Sprintf("stats:risk:%s", result.RiskLevel))
	
	// Increment blocked counter if request was blocked
	if result.BlockRequest {
		g.redisCache.Incr(ctx, "stats:blocked")
	}
}

// Rate limiting middleware
func (g *APIGateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user ID from context (set by auth middleware)
		userID, ok := r.Context().Value("user_id").(string)
		if !ok {
			// If no user ID, use IP address
			userID = r.RemoteAddr
		}

		// Get request category (set by AI middleware)
		category, _ := r.Context().Value("ai_category").(RequestCategory)
		if category == "" {
			category = CategoryStandard
		}
		
		// Adjust rate limits based on category
		var rateLimit int64
		switch category {
		case CategoryAdmin:
			rateLimit = 50  // Admin operations are more limited
		case CategoryAnalytics:
			rateLimit = 200 // Analytics can be frequent
		case CategoryReport:
			rateLimit = 20  // Report generation is resource intensive
		default:
			rateLimit = 100 // Default rate limit
		}

		// Create a Redis key for this user and category
		key := fmt.Sprintf("ratelimit:%s:%s", userID, category)
		
		// Check if user has exceeded rate limit
		pipe := g.redisCache.Pipeline()
		incr := pipe.Incr(r.Context(), key)
		pipe.Expire(r.Context(), key, time.Minute)
		_, err := pipe.Exec(r.Context())
		
		// If Redis isn't working, continue anyway
		if err != nil {
			log.Printf("Redis error in rate limiting: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		count, err := incr.Result()
		if err != nil {
			log.Printf("Rate limit count error: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		if count > rateLimit {
			http.Error(w, fmt.Sprintf("Rate limit exceeded for %s operations", category), http.StatusTooManyRequests)
			return
		}
		
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// Create a reverse proxy to a target backend service
func (g *APIGateway) createReverseProxy(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		
		// Add X-Forwarded headers
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "http") // or "https" if using TLS
		
		// Add custom header to identify the gateway
		req.Header.Set("X-API-Gateway", "ai-powered-gateway")
		
		// Preserve user ID from context if available
		if userID, ok := req.Context().Value("user_id").(string); ok {
			req.Header.Set("X-User-ID", userID)
		}
		
		// Add AI classification headers
		if category, ok := req.Context().Value("ai_category").(RequestCategory); ok {
			req.Header.Set("X-Request-Category", string(category))
		}
		
		if riskLevel, ok := req.Context().Value("ai_risk_level").(RiskLevel); ok {
			req.Header.Set("X-Risk-Level", string(riskLevel))
		}
	}
	
	return proxy
}

// Start the API Gateway
func (g *APIGateway) Start() error {
	log.Printf("Starting AI-Powered API Gateway on port %s", g.config.Port)
	return http.ListenAndServe(":"+g.config.Port, g.router)
}

func main() {
	// Configuration
	config := Config{
		Port: os.Getenv("PORT"),
		BackendServices: map[string]string{
			"users":     "http://localhost:8081",  // Change to real service if available
			"products":  "http://localhost:8082",  // Change to real service if available
			"analytics": "http://localhost:8083",  // Change to real service if available
		},
		RedisAddr:     os.Getenv("REDIS_ADDR"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		RedisDB:       0,
		OpenAIKey:     os.Getenv("OPENAI_API_KEY"),
	}

	// Default values if env vars not set
	if config.Port == "" {
		config.Port = "8080"
	}
	if config.RedisAddr == "" {
		config.RedisAddr = "localhost:6379"
	}
	
	// Log configuration details
	log.Printf("Starting with configuration:")
	log.Printf("- Port: %s", config.Port)
	log.Printf("- Redis: %s", config.RedisAddr)
	log.Printf("- OpenAI API Key: %s", maskString(config.OpenAIKey))
	log.Printf("- Backend services: %d configured", len(config.BackendServices))
	for path, target := range config.BackendServices {
		log.Printf("  * %s -> %s", path, target)
	}

	// Create and start gateway
	gateway, err := NewAPIGateway(config)
	if err != nil {
		log.Fatalf("Failed to initialize API Gateway: %v", err)
	}

	log.Printf("API Gateway initialized successfully")
	log.Printf("Try accessing: http://localhost:%s/health", config.Port)
	log.Printf("Try accessing: http://localhost:%s/dashboard", config.Port)
	log.Printf("Try accessing: http://localhost:%s/api/mock", config.Port)

	if err := gateway.Start(); err != nil {
		log.Fatalf("Failed to start API Gateway: %v", err)
	}
}

// Helper function to mask sensitive strings like API keys
func maskString(s string) string {
	if s == "" {
		return "[not set]"
	}
	if len(s) < 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}