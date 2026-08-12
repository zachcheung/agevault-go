FROM golang:trixie AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /agevault ./cmd/agevault

FROM alpine
COPY --from=build /agevault /usr/local/bin/agevault
WORKDIR /app
ENTRYPOINT ["agevault", "agent-run", "--socket", "/run/agevault-agent/agent.sock", "--"]
CMD ["sh", "-c", "echo REAL_GCP_KMS_TEST=$REAL_GCP_KMS_TEST; echo ---; cat cert.pem"]
