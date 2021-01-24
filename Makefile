build:
	go generate ./...
	go build -o bin/flowlat cmd/flowlat.go

test:
	go generate ./...
	test -z $(gofmt -l ./ | tee /dev/stderr)
	sudo -E go test ./... -count=1 -v
