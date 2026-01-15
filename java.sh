#!/bin/bash

# Native JNI shared library compilation script
#
# This script compiles the native JNI sources into a shared library named
# either libwolfssljni.so/.dylib. Compiling on Linux/Unix and Mac OSX are
# currently supported.
#
# This script will attempt to auto-detect JAVA_HOME location if not set. To
# explicitly use a Java home location, set the JAVA_HOME environment variable
# prior to running this script.
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

OS=`uname`
ARCH=`uname -m`

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

if [ -z "${JAVA_HOME:-}" ]; then
    # if JAVA_HOME not set, detect based on platform/OS
    echo "    JAVA_HOME empty, trying to detect"
else
    # user already set JAVA_HOME, use that
    echo "    JAVA_HOME already set = $JAVA_HOME"
    javaHome="$JAVA_HOME"
fi

if [ -z "${CFLAGS:-}" ]; then
    echo "    CFLAGS = <none>"
else
    echo "    CFLAGS = $CFLAGS"
fi

fpic=""
CFLAGS="${CFLAGS:-}"

# set up Java include and library paths for OS X and Linux
# NOTE: you may need to modify these if your platform uses different locations
if [ "$OS" == "Darwin" ] ; then
    echo "    Detected Darwin/OSX host OS"
    if [ -z "${javaHome:-}" ]; then
        # this is broken since Big Sur, set JAVA_HOME environment var instead
        # OSX JAVA_HOME is typically similar to:
        #    /Library/Java/JavaVirtualMachines/jdk1.8.0_261.jdk/Contents/Home
        javaHome=`/usr/libexec/java_home`
    fi
    javaIncludes="-I$javaHome/include -I$javaHome/include/darwin -I$WOLFSSL_INSTALL_DIR/include"
    javaLibs="-dynamiclib"
    jniLibName="libwolfssljni.dylib"
elif [ "$OS" == "Linux" ] ; then
    echo "    Detected Linux host OS"
    if [ -z "${javaHome:-}" ]; then
        javaHome=`echo $(dirname $(dirname $(readlink -f $(which java))))`
    fi
    if [ ! -d "$javaHome/include" ]
    then
        javaHome=`echo $(dirname $javaHome)`
    fi
    javaIncludes="-I$javaHome/include -I$javaHome/include/linux -I$WOLFSSL_INSTALL_DIR/include"
    javaLibs="-shared"
    jniLibName="libwolfssljni.so"
    if [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "aarch64" ]; then
        fpic="-fPIC"
    fi
else
    echo 'Unknown host OS!'
    exit
fi
echo "        $OS $ARCH"

echo "    Java Home = $javaHome"

# create /lib directory if doesn't exist
if [ ! -d ./lib ]
then
    mkdir ./lib
fi

gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSL.c -o ./native/com_wolfssl_WolfSSL.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLSession.c -o ./native/com_wolfssl_WolfSSLSession.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLContext.c -o ./native/com_wolfssl_WolfSSLContext.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfCryptRSA.c -o ./native/com_wolfssl_WolfCryptRSA.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfCryptECC.c -o ./native/com_wolfssl_WolfCryptECC.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfCryptEccKey.c -o ./native/com_wolfssl_WolfCryptEccKey.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLCertManager.c -o ./native/com_wolfssl_WolfSSLCertManager.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLCertRequest.c -o ./native/com_wolfssl_WolfSSLCertRequest.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLCertificate.c -o ./native/com_wolfssl_WolfSSLCertificate.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLCRL.c -o ./native/com_wolfssl_WolfSSLCRL.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLX509Name.c -o ./native/com_wolfssl_WolfSSLX509Name.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLX509StoreCtx.c -o ./native/com_wolfssl_WolfSSLX509StoreCtx.o $javaIncludes
gcc -Wall -c $fpic $CFLAGS ./native/com_wolfssl_WolfSSLNameConstraints.c -o ./native/com_wolfssl_WolfSSLNameConstraints.o $javaIncludes
gcc -Wall $javaLibs $CFLAGS -o ./lib/$jniLibName ./native/com_wolfssl_WolfSSL.o ./native/com_wolfssl_WolfSSLSession.o ./native/com_wolfssl_WolfSSLContext.o ./native/com_wolfssl_WolfCryptRSA.o ./native/com_wolfssl_WolfCryptECC.o ./native/com_wolfssl_WolfCryptEccKey.o ./native/com_wolfssl_WolfSSLCertManager.o ./native/com_wolfssl_WolfSSLCertRequest.o ./native/com_wolfssl_WolfSSLCertificate.o ./native/com_wolfssl_WolfSSLX509Name.o ./native/com_wolfssl_WolfSSLX509StoreCtx.o ./native/com_wolfssl_WolfSSLNameConstraints.o -L$WOLFSSL_INSTALL_DIR/lib -L$WOLFSSL_INSTALL_DIR/lib64 -l$WOLFSSL_LIBNAME
gcc -Wall $javaLibs $CFLAGS -o ./lib/$jniLibName ./native/com_wolfssl_WolfSSL.o ./native/com_wolfssl_WolfSSLSession.o ./native/com_wolfssl_WolfSSLContext.o ./native/com_wolfssl_WolfCryptRSA.o ./native/com_wolfssl_WolfCryptECC.o ./native/com_wolfssl_WolfCryptEccKey.o ./native/com_wolfssl_WolfSSLCertManager.o ./native/com_wolfssl_WolfSSLCertRequest.o ./native/com_wolfssl_WolfSSLCertificate.o ./native/com_wolfssl_WolfSSLCRL.o ./native/com_wolfssl_WolfSSLX509Name.o ./native/com_wolfssl_WolfSSLX509StoreCtx.o -L$WOLFSSL_INSTALL_DIR/lib -L$WOLFSSL_INSTALL_DIR/lib64 -l$WOLFSSL_LIBNAME
if [ $? != 0 ]; then
    echo "Error creating native JNI library"
    exit 1
fi

echo "    Generated ./lib/$jniLibName"
