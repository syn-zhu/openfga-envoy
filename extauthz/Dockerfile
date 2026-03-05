FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /envoy-extauthz ./cmd/extauthz/

FROM scratch
COPY --from=builder /envoy-extauthz /envoy-extauthz
EXPOSE 9002
ENTRYPOINT ["/envoy-extauthz"]
