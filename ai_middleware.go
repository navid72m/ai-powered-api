// ai_middleware.go
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Buffer size for request bodies
const maxBodySize = 1024 * 1024 // 1MB

// AI middleware to classify and analyze requests
func (g *APIGateway) aiMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := g.tracer.Start(r.Context(), "ai_middleware")
		defer span.End()

		// Check if we should skip AI analysis (e.g., for health checks)
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Read the request body
		var bodyBytes []byte
		var err error

		if r.Body != nil {
			// Limit the body size to avoid memory issues
			bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
			if err != nil {
				span.RecordError(err)
				log.Printf("Error reading request body: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			// Restore the body for the next handlers
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Start a timeout context for the AI analysis
		aiCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Call the AI service to analyze the request
		result, err := g.aiService.AnalyzeRequest(aiCtx, r, bodyBytes)
		if err != nil {
			span.RecordError(err)
			log.Printf("Error analyzing request: %v", err)
			// We'll continue processing the request even if AI analysis fails
			result = &ClassificationResult{
				Category:     CategoryUnknown,
				RiskLevel:    RiskLow,
				Reason:       "Error during analysis: " + err.Error(),
				BlockRequest: false,
			}
		}

		// Add classification information to the span
		span.SetAttributes(
			attribute.String("ai.category", string(result.Category)),
			attribute.String("ai.risk_level", string(result.RiskLevel)),
			attribute.Bool("ai.block_request", result.BlockRequest),
		)

		// Log the classification result
		log.Printf(
			"AI Classification: Path=%s Category=%s RiskLevel=%s Block=%v Reason=%s",
			r.URL.Path, result.Category, result.RiskLevel, result.BlockRequest, result.Reason,
		)

		// Check if we should block this request
		if result.BlockRequest {
			log.Printf("Blocking request: %s %s (Reason: %s)", r.Method, r.URL.Path, result.Reason)
			http.Error(w, "Request blocked: "+result.Reason, http.StatusForbidden)
			return
		}

		// Add the classification information to the request context
		reqWithCategory := r.WithContext(context.WithValue(ctx, "ai_category", result.Category))
		reqWithCategory = reqWithCategory.WithContext(context.WithValue(reqWithCategory.Context(), "ai_risk_level", result.RiskLevel))

		// Add classification headers for backend services
		r.Header.Set("X-Request-Category", string(result.Category))
		r.Header.Set("X-Risk-Level", string(result.RiskLevel))

		// Process the request based on category
		switch result.Category {
		case CategoryAdmin:
			// Admin requests might need special handling
			// For example, more strict authentication or logging
			if result.RiskLevel == RiskHigh {
				// For high-risk admin requests, we might want to require additional verification
				// In a real system, you might redirect to 2FA or notify security team
				log.Printf("High-risk admin request detected: %s %s", r.Method, r.URL.Path)
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
		
		// Continue to the next handler with the enhanced context
		next.ServeHTTP(w, reqWithCategory)
	})
}
