FROM golang:1.22-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-w -s" -o /relay-node .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /relay-node /relay-node
EXPOSE 8080
ENTRYPOINT ["/relay-node"]
