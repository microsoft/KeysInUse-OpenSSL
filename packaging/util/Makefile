GOOS=linux
GOARCH=x86_64
GOFLAGS_COMMON=-ldflags "-linkmode external"

BLD_DIR=$(shell realpath ../../)/bin
KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil

all: $(KEYSINUSEUTIL)

$(KEYSINUSEUTIL):
	go build $(GOFLAGS_COMMON) -o $(KEYSINUSEUTIL) ./keysinuseutil
clean:
	sudo rm -f $(KEYSINUSEUTIL)

.PHONY:
	all
	clean