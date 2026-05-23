FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY . .
RUN go mod tidy && go build -o /orchestrator ./orchestrator/cmd

FROM gcr.io/distroless/base-debian12
COPY --from=builder /orchestrator /orchestrator
ENTRYPOINT ["/orchestrator"]
