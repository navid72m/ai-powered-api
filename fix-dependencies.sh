#!/bin/bash
# fix-dependencies.sh

echo "Fixing Go module dependencies..."

# 1. Backup the existing go.mod if it exists
if [ -f "go.mod" ]; then
  echo "Backing up existing go.mod to go.mod.bak"
  cp go.mod go.mod.bak
fi

# 2. Create a correct go.mod file
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

# 3. Download all dependencies to create go.sum
echo "Downloading dependencies..."
go mod download

# 4. Run go mod tidy to clean up dependencies
echo "Running go mod tidy..."
go mod tidy

echo "Dependencies fixed successfully!"
echo "You can now run your application with: go run main.go"