#!/bin/bash

# Allow user to override which openssl binary is used to verify certs
if [ -z "${OPENSSL}" ]; then
    OPENSSL=openssl
fi

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl.jar:./ -Dsun.boot.library.path=../../lib/ -Xcheck:jni X509CertRequest $@

if [ $? != 0 ]; then
    printf "\nExample failed\n"
    exit -1
else
    printf "\nExample passed\n"
fi

which $OPENSSL > /dev/null
if [ $? != 0 ]; then
    printf "openssl not detected, skipping cert verification\n"
    exit -1
fi

printf "\nVerifying CSRs with openssl...\n"

printf "Testing each can be opened with openssl req -text\n"

# Test reading each DER CSR
CERT_FILES="../certs/generated/csr*.der"
for f in $CERT_FILES
do
    $OPENSSL req -inform DER -in $f -text -noout > /dev/null
    if [ $? != 0 ]; then
        printf "File not readable with openssl req: $f\n"
        exit -1
    fi
done

# Test reading each PEM CSR
CERT_FILES="../certs/generated/csr*.pem"
for f in $CERT_FILES
do
    $OPENSSL req -inform PEM -in $f -text -noout > /dev/null
    if [ $? != 0 ]; then
        printf "File not readable with openssl req: $f\n"
        exit -1
    fi
done

printf "Verification successful\n"
