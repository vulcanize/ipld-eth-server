FROM golang:1.13-alpine as builder

RUN apk --update --no-cache add make git g++ linux-headers
# DEBUG
RUN apk add busybox-extras

# Build ipld-eth-server
WORKDIR /go/src/github.com/vulcanize/ipld-eth-server

# Cache the modules
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

# Build the binary
RUN GCO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o ipld-eth-server .

# Copy migration tool
WORKDIR /
ARG GOOSE_VER="v2.6.0"
ADD https://github.com/pressly/goose/releases/download/${GOOSE_VER}/goose-linux64 ./goose
RUN chmod +x ./goose

# app container
FROM alpine

ARG USER="vdm"
ARG CONFIG_FILE="./environments/example.toml"

RUN adduser -Du 5000 $USER
WORKDIR /app
RUN chown $USER /app
USER $USER

# chown first so dir is writable
# note: using $USER is merged, but not in the stable release yet
COPY --chown=5000:5000 --from=builder /go/src/github.com/vulcanize/ipld-eth-server/$CONFIG_FILE config.toml
COPY --chown=5000:5000 --from=builder /go/src/github.com/vulcanize/ipld-eth-server/entrypoint.sh .


# keep binaries immutable
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/ipld-eth-server ipld-eth-server
COPY --from=builder /goose goose
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/db/migrations migrations/vulcanizedb
COPY --from=builder /go/src/github.com/vulcanize/ipld-eth-server/environments environments

ENTRYPOINT ["/app/entrypoint.sh"]
