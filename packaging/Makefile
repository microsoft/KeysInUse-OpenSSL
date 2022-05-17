LABEL?=~dev
CONFIG?=x86_64
BLD_DIR=$(shell realpath ../)/bin

KEYSINUSEUTIL=$(BLD_DIR)/keysinuseutil
PKGUPLOAD=$(BLD_DIR)/pkgupload

all: $(KEYSINUSEUTIL) deb rpm $(PKGUPLOAD)

deb: $(KEYSINUSEUTIL)
	$(MAKE) -C deb LABEL=$(LABEL) CONFIG=$(CONFIG)

rpm: $(KEYSINUSEUTIL)
	$(MAKE) -C rpm LABEL=$(LABEL) CONFIG=$(CONFIG)

$(KEYSINUSEUTIL):
	$(MAKE) -C util $(KEYSINUSEUTIL)

$(PKGUPLOAD):
	$(MAKE) -C util $(PKGUPLOAD)

clean:
	$(MAKE) -C deb clean
	$(MAKE) -C rpm clean
	$(MAKE) -C util clean

.PHONY:
	all
	clean
	deb
	rpm