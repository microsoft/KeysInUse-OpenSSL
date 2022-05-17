GOOS=linux
GOARCH=x86_64
GOFLAGS_COMMON=-ldflags "-linkmode external"

BLD_DIR=$(shell realpath ../../)/bin
KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil
PKGUPLOAD=$(BLD_DIR)/pkgupload

all: $(KEYSINUSEUTIL) $(PKGUPLOAD)

$(KEYSINUSEUTIL):
	go build $(GOFLAGS_COMMON) -o $(KEYSINUSEUTIL) ./keysinuseutil

$(PKGUPLOAD):
	go build $(GOFLAGS_COMMON) -o $(PKGUPLOAD) ./pkgupload

clean:
	sudo rm -f $(KEYSINUSEUTIL) $(PKGUPLOAD)

.PHONY:
	all
	clean