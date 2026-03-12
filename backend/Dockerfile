# STAGE 1: Build
FROM golang:1.26.1-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o main .

COPY go.mod go.sum ./
RUN go mod download

# STAGE 2: FINAL
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
