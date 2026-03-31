# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o broker ./cmd/broker

# Final stage - minimal image
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/broker .

# Data directory for abuse-detection.db
RUN mkdir -p /data

EXPOSE 8883

ENTRYPOINT ["./broker"]
