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

# Native JNI compilation variables
NATIVE_SRC_DIR  = native
NATIVE_SRCS     = $(wildcard $(NATIVE_SRC_DIR)/*.c)
NATIVE_OBJS     = $(NATIVE_SRCS:.c=.o)
NATIVE_DEPS     = $(NATIVE_SRCS:.c=.d)

CC              ?= gcc
WOLFSSL_INSTALL_DIR ?= $(INSTALL_DIR)
WOLFSSL_LIBNAME ?= wolfssl

# Platform detection
OS              := $(shell uname)
ARCH            := $(shell uname -m)

# JAVA_HOME detection with platform-aware fallback
JAVA_HOME       ?= $(shell \
    if [ "$(OS)" = "Darwin" ]; then \
        /usr/libexec/java_home 2>/dev/null; \
    else \
        java_bin=$$(readlink -f $$(which java) 2>/dev/null); \
        jh=$$(dirname $$(dirname $$java_bin)); \
        if [ ! -d "$$jh/include" ]; then jh=$$(dirname $$jh); fi; \
        echo $$jh; \
    fi)

# Platform-specific flags
ifeq ($(OS),Darwin)
    JNI_INCLUDES  = -I$(JAVA_HOME)/include \
                    -I$(JAVA_HOME)/include/darwin \
                    -I$(WOLFSSL_INSTALL_DIR)/include
    JNI_LIB_FLAGS = -dynamiclib
    JNI_LIB_NAME  = libwolfssljni.dylib
else ifeq ($(OS),Linux)
    JNI_INCLUDES  = -I$(JAVA_HOME)/include \
                    -I$(JAVA_HOME)/include/linux \
                    -I$(WOLFSSL_INSTALL_DIR)/include
    JNI_LIB_FLAGS = -shared
    JNI_LIB_NAME  = libwolfssljni.so
    ifneq ($(filter x86_64 aarch64,$(ARCH)),)
        FPIC = -fPIC
    endif
else
    $(error Unsupported host OS '$(OS)'; supported OSes are Linux and Darwin)
endif

# Optionally enable all patch defines in the native code for testing.
ifeq ($(ENABLE_PATCHES),1)
    PATCH_CFLAGS = $(addprefix -D,$(shell ./scripts/find-wolfssl-pr-patch-defines.sh))
    ifeq ($(PATCH_CFLAGS),)
        $(warning no WOLFSSL_PR*_PATCH_APPLIED defines found; building without patches)
    endif
endif

# Verbose mode: set V=1 to see full compiler commands
ifeq ($(V),1)
    Q =
else
    Q = @
endif

JNI_CFLAGS  = -Wall -Wextra -Werror $(FPIC) -MMD -MP $(PATCH_CFLAGS) $(CFLAGS)
JNI_LDFLAGS = -Wall $(JNI_LIB_FLAGS) $(CFLAGS) \
              -L$(WOLFSSL_INSTALL_DIR)/lib \
              -L$(WOLFSSL_INSTALL_DIR)/lib64
JNI_LDLIBS  = -l$(WOLFSSL_LIBNAME)

.PHONY: all build check native clean-native clean install uninstall dist rpm print-config

all: build

build: build.xml
	$(MAKE) native WOLFSSL_INSTALL_DIR="$(WOLFSSL_INSTALL_DIR)" WOLFSSL_LIBNAME="$(WOLFSSL_LIBNAME)"
	ant

check: build
	ant test

# Pattern rule: compile any native/*.c to native/*.o
$(NATIVE_SRC_DIR)/%.o: $(NATIVE_SRC_DIR)/%.c | print-config
	@echo "  CC      $<"
	$(Q)$(CC) $(JNI_CFLAGS) -c $< -o $@ $(JNI_INCLUDES)

# Link all .o files into the shared library
lib/$(JNI_LIB_NAME): $(NATIVE_OBJS) | lib
	@echo "  LD      $@"
	$(Q)$(CC) $(JNI_LDFLAGS) -o $@ $(NATIVE_OBJS) $(JNI_LDLIBS)

lib:
	mkdir -p lib

# Print build configuration, matching the output style of upstream java.sh
print-config:
	@echo "Compiling Native JNI library:"
	@echo "    WOLFSSL_INSTALL_DIR = $(WOLFSSL_INSTALL_DIR)"
	@echo "    WOLFSSL_LIBNAME     = $(WOLFSSL_LIBNAME)"
	@if [ -n "$(JAVA_HOME)" ]; then \
	    echo "    JAVA_HOME           = $(JAVA_HOME)"; \
	else \
	    echo "    JAVA_HOME           = <not set>"; \
	fi
	@if [ -n "$(CFLAGS)" ]; then \
	    echo "    CFLAGS              = $(CFLAGS)"; \
	else \
	    echo "    CFLAGS              = <none>"; \
	fi
	@echo "    Host OS             = $(OS) $(ARCH)"

# Convenience target for building just native JNI library
native: lib/$(JNI_LIB_NAME)
	@echo "    Generated ./lib/$(JNI_LIB_NAME)"

# Clean only native artifacts (.o, .d files and shared lib)
clean-native:
	$(Q)rm -f $(NATIVE_SRC_DIR)/*.o $(NATIVE_SRC_DIR)/*.d
	$(Q)rm -f lib/$(JNI_LIB_NAME)

# Include auto-generated dependency files (if they exist)
-include $(NATIVE_DEPS)

clean: clean-native
	ant clean cleanjni

install:
	$(INSTALL) -d $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/$(JNI_LIB_NAME) $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/wolfssl.jar $(INSTALL_DIR)/$(LIBDIR)
	$(INSTALL) lib/wolfssl-jsse.jar $(INSTALL_DIR)/$(LIBDIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(LIBDIR)/$(JNI_LIB_NAME)
	rm -f $(INSTALL_DIR)/$(LIBDIR)/wolfssl.jar
	rm -f $(INSTALL_DIR)/$(LIBDIR)/wolfssl-jsse.jar

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
