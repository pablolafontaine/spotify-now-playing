FROM golang:1.19.6-alpine
EXPOSE 8080
ENV PORT="8080"
ENV CLIENT_ID=""
ENV REFRESH_TOKEN=""
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go .client_secret ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /spotify-now-playing
CMD ["/spotify-now-playing"]
