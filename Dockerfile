FROM golang:1.24 as builder

# Add Maintainer Info
LABEL maintainer="Bwire Peter <bwire517@gmail.com>"

WORKDIR /
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the local package files to the container's workspace.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o auth_binary .

FROM gcr.io/distroless/static:nonroot

USER 65532:65532
EXPOSE 80
EXPOSE 50051

WORKDIR /

COPY --from=builder /auth_binary /auth
COPY --from=builder /tmpl /tmpl
COPY --from=builder /localization /localization
COPY --from=builder /migrations /migrations

# Run the service command by default when the container starts.
ENTRYPOINT ["/auth"]
