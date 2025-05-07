# AI-Powered API Gateway

An intelligent reverse proxy that uses AI to classify requests, detect anomalies, and dynamically route API traffic.

## Features

- **High-performance routing** using Go's concurrency model
- **AI-powered request classification** into categories (admin, analytics, report, standard)
- **Anomaly detection** to identify and block suspicious or malicious requests
- **Intelligent rate limiting** based on request category and user profile
- **Full observability** with OpenTelemetry tracing and logging
- **Caching** for both API responses and AI classifications
- **Dashboard** for monitoring Gateway analytics

## Architecture

```
Client → API Gateway → Classification (LLM) → Backend Service
                     ↘ Anomaly detection → Block or Alert
```

1. Client sends a request
2. Gateway checks authentication and rate limits
3. Request content is analyzed by OpenAI (or local AI model)
4. Request is classified and anomalies are detected
5. Gateway routes to the correct backend service or blocks the request
6. Everything is logged to OpenTelemetry

## Components

- **Go Server**: High-performance, concurrent API Gateway
- **Redis**: Store request metadata, rate limits, and classification cache
- **OpenAI API**: AI-powered classification and anomaly detection
- **OpenTelemetry**: Distributed tracing and monitoring

## Setup

### Prerequisites

- Go 1.20 or later
- Docker and Docker Compose
- OpenAI API key

### Environment Variables

Create a `.env` file with the following variables:

```
OPENAI_API_KEY=your_openai_api_key
```

### Running with Docker Compose

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f api-gateway

# Stop all services
docker-compose down
```

### Running Locally for Development

```bash
# Install dependencies
go mod tidy

# Run Redis (required for the gateway)
docker run -d -p 6379:6379 redis:alpine

# Run the API Gateway
go run .
```

## Usage

Once the gateway is running, you can access:

- API Gateway: http://localhost:8080/api/
- Health check: http://localhost:8080/health
- Dashboard: http://localhost:8080/dashboard

### Testing the API Gateway

Use the following endpoints to test different backend services:

- User Service: http://localhost:8080/api/users/
- Product Service: http://localhost:8080/api/products/
- Analytics Service: http://localhost:8080/api/analytics/

Include an `Authorization` header with a Bearer token for authentication:

```
Authorization: Bearer your-token-here
```

### Example Requests

```bash
# Standard request to user service
curl -H "Authorization: Bearer test-token" http://localhost:8080/api/users/

# Admin request to user service
curl -H "Authorization: Bearer test-token" \
     -H "Content-Type: application/json" \
     -d '{"action": "delete", "userId": "123"}' \
     http://localhost:8080/api/users/

# Analytics request
curl -H "Authorization: Bearer test-token" \
     http://localhost:8080/api/analytics/
```

## Customization

### Backend Services

Edit the `BackendServices` map in `main.go` to add or modify backend services:

```go
BackendServices: map[string]string{
    "users":     "http://user-service:8081",
    "products":  "http://product-service:8082",
    "analytics": "http://analytics-service:8083",
    "payments":  "http://payment-service:8084", // Add new service
},
```

### AI Classification

Customize the AI classification prompt in `ai_service.go` to match your specific API patterns and security needs.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.