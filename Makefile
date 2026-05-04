.PHONY: build clean install uninstall run debug

BINARY=killswitch.exe
LDFLAGS=-ldflags="-s -w -H windowsgui"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/killswitch/

build-debug:
	go build -o $(BINARY) ./cmd/killswitch/

clean:
	del /f $(BINARY) 2>nul

install: build
	.\$(BINARY) install

uninstall:
	.\$(BINARY) uninstall

start:
	.\$(BINARY) start

stop:
	.\$(BINARY) stop

status:
	.\$(BINARY) status

debug: build-debug
	.\$(BINARY) debug

tidy:
	go mod tidy

deps:
	go mod download
