FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/appie ./cmd/appie

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/appie /usr/local/bin/appie
USER nobody
EXPOSE 8080
ENTRYPOINT ["appie"]

