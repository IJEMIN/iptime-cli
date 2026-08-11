.PHONY: build test check clean

build:
	mkdir -p bin
	go build -trimpath -o bin/iptime ./cmd/iptime

test:
	go test -race ./...

check:
	test -z "$$(gofmt -l ./cmd ./internal)"
	go mod verify
	go vet ./...
	go test -race ./...
	GOOS=darwin GOARCH=arm64 go build -trimpath -o /tmp/iptime-cli-arm64 ./cmd/iptime
	GOOS=darwin GOARCH=amd64 go build -trimpath -o /tmp/iptime-cli-amd64 ./cmd/iptime

clean:
	rm -f bin/iptime
