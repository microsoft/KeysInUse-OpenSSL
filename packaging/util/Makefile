GOOS=linux
GOARCH=x86_64
GOFLAGS_COMMON=-ldflags "-linkmode external"

BLD_DIR=$(shell realpath ../../)/bin
KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil
KEYID=$(BLD_DIR)/keyid

all: $(KEYSINUSEUTIL) $(KEYID)

$(KEYSINUSEUTIL):
	go build $(GOFLAGS_COMMON) -o $(KEYSINUSEUTIL) ./keysinuseutil

$(KEYID):
	go build $(GOFLAGS_COMMON) -o $(KEYID) ./keyid
clean:
	sudo rm -f $(KEYSINUSEUTIL) $(KEYID)

.PHONY:
	all
	clean