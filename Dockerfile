# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/webproxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 webproxy \
    && adduser -D -u 10001 -G webproxy webproxy
WORKDIR /app
COPY --from=build /out/webproxy /app/webproxy
RUN chown -R webproxy:webproxy /app
USER webproxy
EXPOSE 8080 443
ENTRYPOINT ["/app/webproxy"]
CMD ["-listen", ":8080"]