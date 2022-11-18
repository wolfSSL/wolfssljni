NAME = wolfssl-jni-jsse
VERSION = $(shell grep 'name="implementation.version"' build.xml | sed -re 's/.*value="(.+)".*/\1/')
DIST_FILES = build.xml  COPYING  docs  examples  IDE  java.sh  lib  LICENSING  Makefile  native  platform \
	     README.md  rpm  src

ifneq ($(PREFIX),)
    INSTALL_DIR = $(DESTDIR)$(PREFIX)
else
    INSTALL_DIR = $(DESTDIR)/usr/local
endif

ifeq ($(INSTALL),)
    INSTALL=install
endif

ifeq ($(LIBDIR),)
    LIBDIR=lib
endif


all: build

build:
	./java.sh
	ant

install:
	$(INSTALL) -d $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/libwolfssljni.so $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/wolfssl.jar $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/wolfssl-jsse.jar $(INSTALL_DIR)/$(LIBDIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(LIBDIR)/libwolfssljni.so
	rm -f $(INSTALL_DIR)/share/java/wolfssl.jar
	rm -f $(INSTALL_DIR)/share/java/wolfssl-jsse.jar

dist:
	@mkdir -p "$(NAME)-$(VERSION)"
	@cp -pr $(DIST_FILES) "$(NAME)-$(VERSION)"
	tar -zcf "$(NAME)-$(VERSION).tar.gz" "$(NAME)-$(VERSION)"
	@rm -rf "$(NAME)-$(VERSION)"

rpm: dist
	@rm -f *.rpm
	rpmdev-setuptree
	find ~/rpmbuild/RPMS ~/rpmbuild/SRPMS -name "$(PACKAGE)-$(VERSION)*.rpm" | xargs rm -f
	@cp "$(NAME)-$(VERSION).tar.gz" ~/rpmbuild/SOURCES/
	@cp rpm/spec.in rpm/spec
	@sed -i rpm/spec -e "s/@NAME@/$(NAME)/g"
	@sed -i rpm/spec -e "s/@VERSION@/$(VERSION)/g"
	rpmbuild -ba --clean rpm/spec
	@cp ~/rpmbuild/RPMS/*/$(NAME)-$(VERSION)*.rpm .
	@cp ~/rpmbuild/SRPMS/$(NAME)-$(VERSION)*.rpm .
