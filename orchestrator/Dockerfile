FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY orchestrator/ .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o orchestrator cmd/orchestrator/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /build/orchestrator .

EXPOSE 8080
CMD ["./orchestrator"]
