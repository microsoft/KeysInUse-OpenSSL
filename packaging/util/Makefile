CC?=
CONFIG?=amd64
GOOS?=linux
GOFLAGS_COMMON=-ldflags "-linkmode external"

BLD_DIR=$(shell realpath ../../)/bin
KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil
KEYID=$(BLD_DIR)/keyid

ifeq ($(CONFIG),aarch64)
CC=aarch64-linux-gnu-gcc
GOARCH?=arm64
else
GOARCH?=amd64
endif

all: $(KEYSINUSEUTIL) $(KEYID)

$(KEYSINUSEUTIL):
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) CC=$(CC) go build $(GOFLAGS_COMMON) -o $(KEYSINUSEUTIL) ./keysinuseutil

$(KEYID):
	GOOS=$(GOOS) GOARCH=$(GOARCH) CC=$(CC) go build $(GOFLAGS_COMMON) -o $(KEYID) ./keyid
clean:
	sudo rm -f $(KEYSINUSEUTIL) $(KEYID)

.PHONY:
	all
	clean