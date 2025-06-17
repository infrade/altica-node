APP_NAME=altica_node
PKG=./...
GO=go

.PHONY: all build run test fmt lint clean mod-tidy binding install-binding

all: build

build:
	$(GO) build -o $(APP_NAME) .

run: build
	./$(APP_NAME)

test:
	$(GO) test -v $(PKG)

fmt:
	$(GO) fmt $(PKG)

lint:
	golangci-lint run

clean:
	rm -f $(APP_NAME)

mod-tidy:
	$(GO) mod tidy

binding:
	$(GO) build -o altica_binding ./cmd/binding

install-binding: binding
	mv altica_binding /usr/local/bin/altica-binding
