FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-w -s" -o /smg-relay .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /smg-relay /smg-relay
EXPOSE 8080
ENTRYPOINT ["/smg-relay"]
