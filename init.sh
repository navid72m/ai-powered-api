#!/bin/bash
# init.sh - Initialize the API Gateway project

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Initializing AI-Powered API Gateway project...${NC}"

# Create necessary directories for mock services
echo "Creating directories for mock services..."
mkdir -p mock-services/user-service
mkdir -p mock-services/product-service
mkdir -p mock-services/analytics-service

# Create the HTML files for the mock services
echo "Creating mock service files..."
cat > mock-services/user-service/index.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>User Service</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1 { color: #333; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
    </style>
    <script>
        // Simple script to show the request headers
        window.onload = function() {
            // This would be handled by backend code in a real service
            const responseEl = document.getElementById('response');
            responseEl.textContent = JSON.stringify({
                service: "User Service",
                status: "operational",
                message: "This is a mock user service responding to your request",
                timestamp: new Date().toISOString()
            }, null, 2);
        };
    </script>
</head>
<body>
    <h1>User Service</h1>
    <p>This is a mock User Service for the AI-Powered API Gateway.</p>
    <h2>Response:</h2>
    <pre id="response"></pre>
</body>
</html>
EOL

cat > mock-services/product-service/index.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>Product Service</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1 { color: #333; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
    </style>
    <script>
        // Simple script to show the request headers
        window.onload = function() {
            // This would be handled by backend code in a real service
            const responseEl = document.getElementById('response');
            responseEl.textContent = JSON.stringify({
                service: "Product Service",
                status: "operational",
                message: "This is a mock product service responding to your request",
                products: [
                    { id: 1, name: "Product A", price: 19.99 },
                    { id: 2, name: "Product B", price: 29.99 },
                    { id: 3, name: "Product C", price: 39.99 }
                ],
                timestamp: new Date().toISOString()
            }, null, 2);
        };
    </script>
</head>
<body>
    <h1>Product Service</h1>
    <p>This is a mock Product Service for the AI-Powered API Gateway.</p>
    <h2>Response:</h2>
    <pre id="response"></pre>
</body>
</html>
EOL

cat > mock-services/analytics-service/index.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>Analytics Service</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1 { color: #333; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
    </style>
    <script>
        // Simple script to show the request headers
        window.onload = function() {
            // This would be handled by backend code in a real service
            const responseEl = document.getElementById('response');
            responseEl.textContent = JSON.stringify({
                service: "Analytics Service",
                status: "operational",
                message: "This is a mock analytics service responding to your request",
                metrics: {
                    visitors: 12453,
                    pageViews: 45678,
                    conversionRate: 2.34,
                    averageSessionTime: "3m 45s"
                },
                timestamp: new Date().toISOString()
            }, null, 2);
        };
    </script>
</head>
<body>
    <h1>Analytics Service</h1>
    <p>This is a mock Analytics Service for the AI-Powered API Gateway.</p>
    <h2>Response:</h2>
    <pre id="response"></pre>
</body>
</html>
EOL

# Create a simple Go file for go.mod initialization
echo "Creating main package for initialization..."
cat > main.go << 'EOL'
// main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// Placeholder for full implementation
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "AI-Powered API Gateway")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
EOL

# Create a basic go.mod file directly (skipping go mod init)
echo "Creating go.mod file..."
cat > go.mod << 'EOL'
module github.com/yourusername/ai-api-gateway

go 1.20

require (
	github.com/go-redis/redis/v8 v8.11.5
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.42.0
	go.opentelemetry.io/otel v1.16.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.16.0
	go.opentelemetry.io/otel/sdk v1.16.0
	go.opentelemetry.io/otel/trace v1.16.0
)
EOL

# Create .env file for OpenAI API key
if [ ! -f .env ]; then
    echo "Creating .env file..."
    echo "OPENAI_API_KEY=your_openai_api_key" > .env
    echo -e "${YELLOW}Please edit the .env file to add your real OpenAI API key${NC}"
fi

# Make test script executable
echo "Making test script executable..."
chmod +x test.sh

# Use simplified Dockerfile
echo "Using simplified Dockerfile..."
mv simplified-dockerfile Dockerfile

echo -e "${GREEN}Initialization complete!${NC}"
echo -e "You can now run: ${YELLOW}docker compose up -d${NC}"
echo -e "After the services are running, test with: ${YELLOW}./test.sh${NC}"