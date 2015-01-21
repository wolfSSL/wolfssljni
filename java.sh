#!/bin/bash

OS=`uname`
ARCH=`uname -m`

# set up Java include and library paths for OS X and Linux
# NOTE: you may need to modify these if your platform uses different locations
if [ "$OS" == "Darwin" ] ; then
    javaIncludes="-I/System/Library/Frameworks/JavaVM.framework/Headers"
    javaLibs="-dynamiclib -framework JavaVM"
    jniLibName="libwolfssl.jnilib"
    cflags="-DHAVE_ECC"
elif [ "$OS" == "Linux" ] ; then
    javaIncludes="-I/usr/lib/jvm/java-8-oracle/include -I/usr/lib/jvm/java-8-oracle/include/linux"
    javaLibs="-shared"
    jniLibName="libwolfSSL.so"
    cflags="-DHAVE_ECC -DUSE_FAST_MATH"
    if [ "$ARCH" == "x86_64" ] ; then
        fpic="-fPIC"
    else
        fpic=""
    fi
else
    echo 'Unknown host OS!'
    exit
fi

# create /lib directory if doesn't exist
if [ ! -d ./lib ]
then
    mkdir ./lib
fi

gcc -DWOLFSSL_DTLS -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSL.c -o ./native/com_wolfssl_WolfSSL.o $javaIncludes
gcc -DWOLFSSL_DTLS -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLSession.c -o ./native/com_wolfssl_WolfSSLSession.o $javaIncludes
gcc -DWOLFSSL_DTLS -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLContext.c -o ./native/com_wolfssl_WolfSSLContext.o $javaIncludes
gcc -DWOLFSSL_DTLS -Wall -c $fpic $cflags ./native/com_wolfssl_wolfcrypt_RSA.c -o ./native/com_wolfssl_wolfcrypt_RSA.o $javaIncludes
gcc -DWOLFSSL_DTLS -Wall -c $fpic $cflags ./native/com_wolfssl_wolfcrypt_ECC.c -o ./native/com_wolfssl_wolfcrypt_ECC.o $javaIncludes
gcc -Wall $javaLibs $cflags -o ./lib/$jniLibName ./native/com_wolfssl_WolfSSL.o ./native/com_wolfssl_WolfSSLSession.o ./native/com_wolfssl_WolfSSLContext.o ./native/com_wolfssl_wolfcrypt_RSA.o ./native/com_wolfssl_wolfcrypt_ECC.o -lwolfssl

