CC?=
CONFIG?=amd64
GOOS?=linux

BLD_DIR=$(shell realpath ../../)/bin
KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil
KEYID=$(BLD_DIR)/keyid

ifeq ($(CONFIG),aarch64)
# Cross-compiling
ifneq ($(shell uname -p),aarch64)
CC=aarch64-linux-gnu-gcc
endif

GOARCH?=arm64
else
GOARCH?=amd64
endif

all: $(KEYSINUSEUTIL) $(KEYID)

$(KEYSINUSEUTIL):
	# gcc -fPIC -c -o ./keysinuseutil/libc_wrappers.o ./keysinuseutil/libc_wrappers.c
	# ld -r -o ./keysinuseutil/libc_wrappers.a ./keysinuseutil/libc_wrappers.o
	CGO_ENABLED=1 CGO_LDFLAGS='-lcrypto' CC=$(CC) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build \
		-ldflags "-extldflags '-Wl,--wrap=pthread_sigmask,--wrap=pthread_create,--wrap=pthread_detach,--wrap=pthread_attr_getstacksize' -linkmode external" \
		-o $(KEYSINUSEUTIL) ./keysinuseutil

$(KEYID):
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "-linkmode external" -o $(KEYID) ./keyid
clean:
	sudo rm -f $(KEYSINUSEUTIL) $(KEYID)

.PHONY:
	all
	clean