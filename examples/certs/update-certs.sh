#!/bin/bash

# Example Certificate and Key Update Script
#
# This script is used to update all example certificates and keys by copying
# them over from a specified wolfSSL library directory.
#
# Script should be run from the <wolfssljni>/examples/certs directory.
# One argument should be provided, the path to a wolfSSL directory's "cert"
# directory.
#
# Script behavior:
#
#   1. Copy certs from wolfSSL certs directory to this certs directory.
#   2. Convert certs from PEM to DER where needed.
#   3. Remove text info from intermediate certs (for Android use)
#
# Certs not updated, which need to be checked/updated manually if needed:
#
#   1. ca-google-root.der
#   2. example-com.der

printf "Removing and updating example certificates and keys\n"
if [ -z "$1" ]; then
    printf "\tNo directory to certs provided\n"
    printf "\tExample use ./update-certs.sh ~/wolfssl/certs\n"
    exit 1;
fi
CERT_LOCATION=$1

# Copy cert files from wolfssl/certs to local examples/certs
certList=(
    "ca-cert.pem"
    "ca-ecc-cert.pem"
    "ca-ecc-key.pem"
    "ca-key.pem"
    "ca-key.der"
    "client-cert.der"
    "client-cert.pem"
    "client-key.pem"
    "client-key.der"
    "client-keyPub.der"
    "dh2048.pem"
    "ecc-client-key.der"
    "ecc-client-key.pem"
    "ecc-key.pem"
    "server-cert.pem"
    "server-ecc.pem"
    "server-key.pem"
    "crl/cliCrl.pem"
    "crl/crl.pem"
    "crl/crl.revoked"
    "crl/eccCliCRL.pem"
    "crl/eccSrvCRL.pem"
    "intermediate/ca-int2-cert.pem"
    "intermediate/ca-int2-ecc-cert.pem"
    "intermediate/ca-int-cert.pem"
    "intermediate/ca-int-ecc-cert.pem"
    "intermediate/server-int-cert.pem"
    "intermediate/server-int-ecc-cert.pem"
)

for i in ${!certList[@]};
do
    printf "Updating: ${certList[$i]}\n"
    cp $CERT_LOCATION/${certList[$i]} ./${certList[$i]}
    if [ $? -ne 0 ]; then
        printf "Failed to copy cert: ${certList[$i]}\n"
        exit 1
    fi
done

# Copy OCSP certs (stored flat, not in subdirectory)
printf "Updating: ocsp-root-ca-cert.pem\n"
cp $CERT_LOCATION/ocsp/root-ca-cert.pem ./ocsp-root-ca-cert.pem
if [ $? -ne 0 ]; then
    printf "Failed to copy cert: ocsp/root-ca-cert.pem\n"
    exit 1
fi

printf "Updating: ocsp-intermediate1-ca-cert.pem\n"
cp $CERT_LOCATION/ocsp/intermediate1-ca-cert.pem ./ocsp-intermediate1-ca-cert.pem
if [ $? -ne 0 ]; then
    printf "Failed to copy cert: ocsp/intermediate1-ca-cert.pem\n"
    exit 1
fi

# Generate ca-keyPkcs8.der, used by examples/X509CertificateGeneration.java
openssl pkcs8 -topk8 -inform DER -outform DER -in ca-key.der -out ca-keyPkcs8.der -nocrypt
if [ $? -ne 0 ]; then
    printf "Failed to generate ca-keyPkcs8.der"
    exit 1
fi
printf "Generated ca-keyPkcs8.der\n"

# Remove text info from intermediate certs, causes issues on Android (WRONG TAG)
printf "Removing text info from intermediate certs\n"
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' ca-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' ca-ecc-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int2-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int2-ecc-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/ca-int-ecc-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/server-int-cert.pem
sed -i.bak -n '/-----BEGIN CERTIFICATE-----/,$p' intermediate/server-int-ecc-cert.pem

# Remvoe sed .bak files
rm intermediate/ca-int2-cert.pem.bak
rm intermediate/ca-int2-ecc-cert.pem.bak
rm intermediate/ca-int-cert.pem.bak
rm intermediate/ca-int-ecc-cert.pem.bak
rm intermediate/server-int-cert.pem.bak
rm intermediate/server-int-ecc-cert.pem.bak

printf "Finished successfully\n"

