include ../makeenv

LABEL?=~dev
CONFIG?=amd64
VER=$(VERSION)-$(LABEL)
PKG_COMMON=../common
PKG_DIR=../../pkg

ifeq ($(CONFIG),aarch64)
ARCH=arm64
BLD_DIR=../../bin/linux_arm64
else
ARCH=amd64
BLD_DIR=../../bin
endif

BUILD_TMP=$(abspath ../../build-tmp/)
FAKEROOT=$(BUILD_TMP)/fake-root
DOCDIR=$(FAKEROOT)/usr/share/doc/$(PACKAGE)
LIBDIR=$(FAKEROOT)/usr/lib/keysinuse

UTIL=$(BLD_DIR)/keysinuseutil
ENGINE=$(BLD_DIR)/keysinuse.so

DEB=$(PKG_DIR)/$(PACKAGE)-$(VER).$(ARCH).deb

package: $(DEB)

$(DEB): $(FAKEROOT) $(FAKEROOT)/DEBIAN
	-mkdir -p $(PKG_DIR)
	-rm -f $@
	sudo chown -R root.root $(FAKEROOT)
	sudo dpkg-deb -v -b $(FAKEROOT) $@

$(FAKEROOT)/DEBIAN: control ../../LICENSE $(PKG_COMMON)/changelog $(PKG_COMMON)/preinst $(PKG_COMMON)/postinst $(PKG_COMMON)/prerm
	-rm -rf $(FAKEROOT)/DEBIAN
	-mkdir -p $(FAKEROOT)/DEBIAN
	cp control $(PKG_COMMON)/preinst $(PKG_COMMON)/postinst $(PKG_COMMON)/prerm $(FAKEROOT)/DEBIAN
	sudo chmod 755 $(FAKEROOT)/DEBIAN
	chmod 644 $(FAKEROOT)/DEBIAN/*
	chmod 755 $(FAKEROOT)/DEBIAN/post*
	chmod 755 $(FAKEROOT)/DEBIAN/pre*
	sed -i '/^Version:/c Version: $(VER)' $(FAKEROOT)/DEBIAN/control
	sed -i '/^Package:/c Package: $(PACKAGE)' $(FAKEROOT)/DEBIAN/control
	sed -i '/^Architecture:/c Architecture: $(ARCH)' $(FAKEROOT)/DEBIAN/control

.PHONY: clean install-clean

clean: install-clean
	sudo rm -f $(BUILD_TMP)/$(PACKAGE)*.deb

install-clean:
	sudo rm -rf $(FAKEROOT)

$(FAKEROOT): install-clean $(UTIL)
	mkdir -p $(LIBDIR) $(DOCDIR)
	install -m 755 $(UTIL) $(LIBDIR)
	install -m 644 $(ENGINE) $(LIBDIR)
	cp ../../LICENSE $(DOCDIR)/copyright
	cat $(PKG_COMMON)/changelog | gzip -9 > $(DOCDIR)/changelog.Debian.gz
