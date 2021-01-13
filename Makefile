build:
	GOOS=linux GOARCH=amd64 go build -o audit-cli cmd/libauditgo-cli.go

test:
	go test ./...

pre-commit:
	# Setup an alias "gitos" that has your opensource git profile configured.
	# atleast user.name and user.email
	@gitos
	@go test ./...
	@go fmt ./...
	@goimports -w .
	# @golint ./...
	@go vet ./...
	@go mod tidy

deps:
	@echo "Installing tools goimports, golint, gocyclo"
	@go get -u golang.org/x/lint/golint
	@go get -u github.com/fzipp/gocyclo
	@go get golang.org/x/tools/cmd/goimports
	@echo "Setting up pre-commit hook"
	@ln -snf ../../.pre-commit .git/hooks/pre-commit
	@chmod +x .pre-commit



