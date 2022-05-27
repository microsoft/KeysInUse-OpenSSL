
include ../makeenv

LABEL?=~dev
CONFIG?=x86_64
PKG_COMMON=../common
PKG_DIR=../../pkg

ifeq ($(CONFIG),aarch64)
ARCH=aarch64
TARGET=aarch64-microsoft-linux
BLD_DIR=../../bin/linux_arm64
else
ARCH=x86_64
TARGET=x86_64-microsoft-linux
BLD_DIR=../../bin
endif

BUILD_TMP=$(abspath ../../build-tmp/)
DATAROOT=$(BUILD_TMP)/data-root
FAKEROOT=$(DATAROOT)/$(PACKAGE)-$(VERSION)
DOCDIR=$(FAKEROOT)/usr/share/doc/$(PACKAGE)
LIBDIR=$(FAKEROOT)/usr/lib/keysinuse

RPM=$(BUILD_TMP)/RPMS/$(ARCH)/$(PACKAGE)-$(VERSION)-$(LABEL).$(ARCH).rpm

TARBALL=$(BUILD_TMP)/SOURCES/$(PACKAGE)-$(VERSION).tgz

UTIL=$(BLD_DIR)/keysinuseutil
ENGINE=$(BLD_DIR)/keysinuse.so

$(RPM): $(TARBALL)
	mkdir -p $(PKG_DIR)
	rpmbuild -v -bb --clean --define "_topdir $(BUILD_TMP)" $(BUILD_TMP)/SPECS/keysinuse.spec

$(TARBALL): rpm_prepare install-deps $(DOCDIR)/ChangeLog
	find $(FAKEROOT) -type d | xargs chmod 0755
	find $(FAKEROOT) -type d | xargs chmod ug-s
	cd $(DATAROOT) && tar -czf $@ *

$(DOCDIR):
	mkdir -p $@

$(DOCDIR)/ChangeLog: $(PKG_COMMON)/changelog $(DOCDIR)
	cp $< $@

rpm_prepare:
	mkdir -p $(BUILD_TMP)/SOURCES $(BUILD_TMP)/SPECS $(BUILD_TMP)/BUILD $(BUILD_TMP)/BUILDROOT $(BUILD_TMP)/RPMS $(BUILD_TMP)/SRPMS
	cp keysinuse.spec $(BUILD_TMP)/SPECS
	sed -i 's|PKG-DIR|$(PKG_DIR)|' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i '/^Name:/c Name: $(PACKAGE)' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i '/^Version:/c Version: $(VERSION)' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i '/^Release:/c Release: $(LABEL)' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i -e '/^PRE-INSTALL/{r $(PKG_COMMON)/preinst' -e 'd}' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i -e '/^POST-INSTALL/{r $(PKG_COMMON)/postinst' -e 'd}' $(BUILD_TMP)/SPECS/keysinuse.spec
	sed -i -e '/^PRE-UNINSTALL/{r $(PKG_COMMON)/prerm' -e 'd}' $(BUILD_TMP)/SPECS/keysinuse.spec

.PHONY: clean install-clean install-deps

clean: install-clean
	-rm -rf $(BUILD_TMP)/SOURCES $(BUILD_TMP)/SPECS $(BUILD_TMP)/BUILD $(BUILD_TMP)/BUILDROOT $(BUILD_TMP)/RPMS $(BUILD_TMP)/SRPMS

install-clean:
	-rm -rf $(DATAROOT)

install-deps: install-clean	$(EXECS)
	mkdir -p $(LIBDIR)
	install -m 755 $(UTIL) /usr/bin
	install -m 755 $(ENGINE) $(LIBDIR)
