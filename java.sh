#!/bin/bash

# Native JNI shared library compilation script
#
# This script compiles the native JNI sources into a shared library named
# either libwolfssljni.so/.dylib by invoking the Makefile native target.
# Compiling on Linux/Unix and Mac OSX are currently supported.
#
# JAVA_HOME detection is handled by the Makefile. To explicitly use a Java
# home location, set the JAVA_HOME environment variable prior to running
# this script.
#
# This script will try to link against a wolfSSL library installed to the
# default location of /usr/local. This script accepts two arguments on the
# command line. The first argument can point to a custom wolfSSL installation
# location. A custom install location would match the directory set at wolfSSL
# ./configure --prefix=<DIR>.
#
# The second argument represents the wolfSSL library name that should be
# linked against. This is helpful if a non-standard library name has been
# used with wolfSSL, for example the ./configure --with-libsuffix option
# has been used to add a suffix to the wolfSSL library name. Note that to
# use this argument, an installation location must be specified via the
# first argument.
#
# For example, if wolfSSL was configured with --with-libsuffix=jsse, then
# this script could be called like so using the default installation
# path of /usr/local.
#
# java.sh /usr/local wolfssljsse

# Fail on any errors
set -euo pipefail

if [ -z "${1-}" ]; then
    # default install location is /usr/local
    WOLFSSL_INSTALL_DIR="/usr/local"
else
    # use custom wolfSSL install location
    # should match directory set at wolfSSL ./configure --prefix=<DIR>
    WOLFSSL_INSTALL_DIR="$1"
fi

if [ -z "${2-}" ]; then
    # default wolfSSL library name is libwolfssl
    WOLFSSL_LIBNAME="wolfssl"
else
    # use custom wolfSSL library name
    # should match wolfsslSUFFIX as set using ./configure --with-libsuffix
    WOLFSSL_LIBNAME="$2"
fi

echo "Compiling Native JNI library:"
echo "    WOLFSSL_INSTALL_DIR = $WOLFSSL_INSTALL_DIR"
echo "    WOLFSSL_LIBNAME    = $WOLFSSL_LIBNAME"

# Do a clean build of the native library to preserve legacy script behavior.
make clean-native native \
    WOLFSSL_INSTALL_DIR="$WOLFSSL_INSTALL_DIR" \
    WOLFSSL_LIBNAME="$WOLFSSL_LIBNAME"
