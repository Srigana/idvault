.PHONY: build test demo run dev clean

build:
	go build -o bin/idvault ./cmd/idvault

test:
	go vet ./...
	go test -race -count=1 ./...

demo:
	go run ./cmd/idvault demo

run: build
	./bin/idvault serve -addr :8080 -data ./data

dev: build
	./bin/idvault serve -dev -addr 127.0.0.1:8080 -data ./data-dev

clean:
	rm -rf bin data data-dev
