FROM golang:1.24 AS builder

WORKDIR /app

# Copy go.mod and go.sum files from the project root
COPY go.mod go.sum ./
RUN go mod download

# Copy project files
COPY ./apps/tenancy ./apps/tenancy
COPY ./internal ./internal

# Build the binary from the cmd directory
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o /app/binary ./apps/tenancy/cmd/main.go

FROM gcr.io/distroless/static:nonroot

USER 65532:65532
EXPOSE 80
EXPOSE 50051

WORKDIR /

COPY --from=builder /app/binary /tenancy
COPY --from=builder /app/apps/tenancy/migrations /migrations

# Run the service command by default when the container starts.
ENTRYPOINT ["/tenancy"]
