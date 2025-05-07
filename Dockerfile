# Simplified Dockerfile
FROM golang:1.20-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# First copy only the source code
COPY *.go ./
COPY go.mod ./

# Initialize the module
RUN go mod init github.com/yourusername/ai-api-gateway 2>/dev/null || true
RUN go mod tidy

# Copy the rest of the application
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o api-gateway .

# Use a smaller image for the final container
FROM alpine:latest

# Install CA certificates for HTTPS connections
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/api-gateway .

# Expose the port
EXPOSE 8080

# Run the application
CMD ["./api-gateway"]