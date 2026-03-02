FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
  go build -trimpath -ldflags="-s -w" -o /out/core ./cmd

FROM alpine:3.21

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/core /usr/local/bin/core

ENTRYPOINT ["core"]
