#!/bin/bash

# Allow user to override which openssl binary is used to verify certs
if [ -z "${OPENSSL}" ]; then
    OPENSSL=openssl
fi

cd ./examples/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib/:/usr/local/lib
java -classpath ../../lib/wolfssl.jar:./ -Dsun.boot.library.path=../../lib/ -Xcheck:jni X509v3CertificateGeneration $@

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

printf "\nVerifying certs with openssl...\n"

printf "Testing each can be opened with openssl x509 -text\n"

# Test reading each DER cert
CERT_FILES="../certs/generated/*.der"
for f in $CERT_FILES
do
    $OPENSSL x509 -inform DER -in $f -text -noout > /dev/null
    if [ $? != 0 ]; then
        printf "File not readable with openssl x509: $f\n"
        exit -1
    fi
done

# Test reading each PEM cert
CERT_FILES="../certs/generated/*.pem"
for f in $CERT_FILES
do
    $OPENSSL x509 -inform PEM -in $f -text -noout > /dev/null
    if [ $? != 0 ]; then
        printf "File not readable with openssl x509: $f\n"
        exit -1
    fi
done

printf "Verification successful\n"
