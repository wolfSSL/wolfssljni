#!/bin/bash

OS=`uname`
ARCH=`uname -m`

if [ -z "$1" ]; then
    # default install location is /usr/local
    WOLFSSL_INSTALL_DIR="/usr/local"
else
    # use custom wolfSSL install location
    # should match directory set at wolfSSL ./configure --prefix=<DIR>
    WOLFSSL_INSTALL_DIR=$1
fi

echo "Compiling Native JNI library:"
echo "    WOLFSSL_INSTALL_DIR = $WOLFSSL_INSTALL_DIR"

# set up Java include and library paths for OS X and Linux
# NOTE: you may need to modify these if your platform uses different locations
if [ "$OS" == "Darwin" ] ; then
    echo "    Detected Darwin/OSX host OS"
    javaHome=`/usr/libexec/java_home`
    javaIncludes="-I$javaHome/include -I$javaHome/include/darwin -I$WOLFSSL_INSTALL_DIR/include"
    javaLibs="-dynamiclib -framework JavaVM"
    jniLibName="libwolfssljni.jnilib"
    cflags="-DHAVE_ECC"
elif [ "$OS" == "Linux" ] ; then
    echo "    Detected Linux host OS"
    javaHome=`echo $(dirname $(dirname $(readlink -f $(which java))))`
    if [ ! -d "$javaHome/include" ]
    then
        javaHome=`echo $(dirname $javaHome)`
    fi
    javaIncludes="-I$javaHome/include -I$javaHome/include/linux -I$WOLFSSL_INSTALL_DIR/include"
    javaLibs="-shared"
    jniLibName="libwolfssljni.so"
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

gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSL.c -o ./native/com_wolfssl_WolfSSL.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLSession.c -o ./native/com_wolfssl_WolfSSLSession.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLContext.c -o ./native/com_wolfssl_WolfSSLContext.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_wolfcrypt_RSA.c -o ./native/com_wolfssl_wolfcrypt_RSA.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_wolfcrypt_ECC.c -o ./native/com_wolfssl_wolfcrypt_ECC.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_wolfcrypt_EccKey.c -o ./native/com_wolfssl_wolfcrypt_EccKey.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLCertManager.c -o ./native/com_wolfssl_WolfSSLCertManager.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLCertificate.c -o ./native/com_wolfssl_WolfSSLCertificate.o $javaIncludes
gcc -Wall -c $fpic $cflags ./native/com_wolfssl_WolfSSLX509StoreCtx.c -o ./native/com_wolfssl_WolfSSLX509StoreCtx.o $javaIncludes
gcc -Wall $javaLibs $cflags -o ./lib/$jniLibName ./native/com_wolfssl_WolfSSL.o ./native/com_wolfssl_WolfSSLSession.o ./native/com_wolfssl_WolfSSLContext.o ./native/com_wolfssl_wolfcrypt_RSA.o ./native/com_wolfssl_wolfcrypt_ECC.o ./native/com_wolfssl_wolfcrypt_EccKey.o ./native/com_wolfssl_WolfSSLCertManager.o ./native/com_wolfssl_WolfSSLCertificate.o ./native/com_wolfssl_WolfSSLX509StoreCtx.o -L$WOLFSSL_INSTALL_DIR/lib -lwolfssl

echo "    Generated ./lib/$jniLibName"
