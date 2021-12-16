FROM golang:1.17-bullseye as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build

FROM debian:bullseye-slim

WORKDIR /app

COPY --from=builder /app/vouch /app

ENTRYPOINT ["/app/vouch"]
