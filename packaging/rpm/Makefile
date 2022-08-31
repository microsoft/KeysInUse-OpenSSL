
include ../makeenv

LABEL?=~dev
CONFIG?=x86_64
BLD_DIR=../../bin

ifeq ($(CONFIG),aarch64)
ARCH=aarch64
TARGET=aarch64-microsoft-linux
else
ARCH=x86_64
TARGET=x86_64-microsoft-linux
endif

PROJECT_ROOT=$(abspath ../../)
BUILD_TMP=$(PROJECT_ROOT)/build-tmp/
DATAROOT=$(BUILD_TMP)/data-root
FAKEROOT=$(DATAROOT)/$(PACKAGE)-$(VERSION)
DOCDIR=$(FAKEROOT)/usr/share/doc/$(PACKAGE)
LICENSEDIR=$(FAKEROOT)/usr/share/licenses/$(PACKAGE)
LIBDIR=$(FAKEROOT)/usr/lib/keysinuse
BINDIR=$(FAKEROOT)/usr/bin

PKG_COMMON=$(PROJECT_ROOT)/packaging/common
PKG_DIR=$(PROJECT_ROOT)/pkg

RPM=$(BUILD_TMP)/RPMS/$(ARCH)/$(PACKAGE)-$(VERSION)-$(LABEL).$(ARCH).rpm

TARBALL=$(BUILD_TMP)/SOURCES/$(PACKAGE)-$(VERSION).tgz

UTIL=$(BLD_DIR)/keysinuseutil
ENGINE=$(BLD_DIR)/keysinuse.so

$(RPM): $(TARBALL)
	mkdir -p $(PKG_DIR)
	rpmbuild -v -bb --target $(ARCH) --clean --define "_topdir $(BUILD_TMP)" $(BUILD_TMP)/SPECS/keysinuse.spec

$(TARBALL): rpm_prepare install-deps $(DOCDIR)/ChangeLog $(LICENSEDIR)/LICENSE
	find $(FAKEROOT) -type d | xargs chmod 0755
	find $(FAKEROOT) -type d | xargs chmod ug-s
	cd $(DATAROOT) && tar -czf $@ *

$(LICENSEDIR):
	mkdir -p $@

$(LICENSEDIR)/LICENSE: $(PROJECT_ROOT)/LICENSE $(LICENSEDIR)
	cp $< $@

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
	mkdir -p $(LIBDIR) $(BINDIR)
	install -m 755 $(UTIL) $(BINDIR)
	install -m 755 $(ENGINE) $(LIBDIR)
