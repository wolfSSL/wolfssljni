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
    "test/cert-ext-nc.pem"
    "test/cert-ext-ncip.pem"
    "test/cert-ext-ncdns.pem"
    "test/cert-ext-nc-combined.pem"
    "test/cert-ext-ncmulti.pem"
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

# Generate CRL Distribution Points test cert
printf "Generating test/crl-dp-cert.pem\n"
mkdir -p test
TMP_DIR="$(mktemp -d)"
cat > "${TMP_DIR}/openssl.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[ dn ]
CN = Test CRL DP
O = wolfSSL Test
C = US

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
crlDistributionPoints = URI:http://crl.example.com/test.crl
EOF

openssl req -new -newkey rsa:2048 -nodes -x509 -days 365 \
  -keyout "${TMP_DIR}/crl-dp-key.pem" -out test/crl-dp-cert.pem \
  -config "${TMP_DIR}/openssl.cnf" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    printf "Failed to generate test/crl-dp-cert.pem\n"
    rm -rf "${TMP_DIR}"
    exit 1
fi
rm -rf "${TMP_DIR}"

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

# Remove sed .bak files
rm intermediate/ca-int2-cert.pem.bak
rm intermediate/ca-int2-ecc-cert.pem.bak
rm intermediate/ca-int-cert.pem.bak
rm intermediate/ca-int-ecc-cert.pem.bak
rm intermediate/server-int-cert.pem.bak
rm intermediate/server-int-ecc-cert.pem.bak

# Generate test CRL (PEM and DER) for WolfSSLCRL decode testing.
# Creates a self-signed CA, revokes a dummy serial, produces CRL in
# both PEM and DER formats under test/.
printf "\nGenerating test CRL for CRL decode testing...\n"
TMP_DIR="$(mktemp -d)"

# CA key + self-signed cert
openssl genrsa -out "${TMP_DIR}/crl-test-ca-key.pem" 2048 2>/dev/null
openssl req -x509 -new -nodes \
  -key "${TMP_DIR}/crl-test-ca-key.pem" \
  -sha256 -days 3650 \
  -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL Inc./OU=Development Test/CN=wolfSSL Test CA" \
  -out "${TMP_DIR}/crl-test-ca-cert.pem" 2>/dev/null

# CRL index / database files required by openssl ca
touch "${TMP_DIR}/index.txt"
echo "01" > "${TMP_DIR}/crlnumber"

cat > "${TMP_DIR}/openssl-ca.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database       = ${TMP_DIR}/index.txt
crlnumber      = ${TMP_DIR}/crlnumber
default_md     = sha256
default_crl_days = 3650

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

# Generate CRL with empty revocation list. Decode tests only need to parse
# the CRL structure (issuer, signature, dates, etc.), not iterate entries.
openssl ca -gencrl \
  -keyfile "${TMP_DIR}/crl-test-ca-key.pem" \
  -cert "${TMP_DIR}/crl-test-ca-cert.pem" \
  -config "${TMP_DIR}/openssl-ca.cnf" \
  -out test/crl-decode.pem 2>/dev/null
if [ $? -ne 0 ]; then
    printf "Failed to generate test/crl-decode.pem\n"
    rm -rf "${TMP_DIR}"
    exit 1
fi

# Convert PEM CRL to DER
openssl crl -in test/crl-decode.pem -outform DER \
  -out test/crl-decode.der 2>/dev/null
if [ $? -ne 0 ]; then
    printf "Failed to generate test/crl-decode.der\n"
    rm -rf "${TMP_DIR}"
    exit 1
fi
rm -rf "${TMP_DIR}"
printf "Generated test/crl-decode.pem and test/crl-decode.der\n"

# Generate SAN test certificates for WolfSSLAltName testing
printf "\nGenerating SAN test certificates...\n"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/generate-san-test-certs.sh" ]; then
    "$SCRIPT_DIR/generate-san-test-certs.sh"
    if [ $? -ne 0 ]; then
        printf "Failed to generate SAN test certificates\n"
        exit 1
    fi
else
    printf "Warning: generate-san-test-certs.sh not found, skipping SAN certs\n"
fi

printf "\nFinished successfully\n"
