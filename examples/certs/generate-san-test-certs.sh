#!/bin/bash

# SAN Test Certificate Generation Script
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This script generates test certificates with various Subject Alternative Name
# (SAN) types for testing WolfSSLAltName functionality.
#
# Script should be run from the <wolfssljni>/examples/certs directory.
#
# Generated certificates:
#   - san-test-ca-key.pem / san-test-ca-cert.pem: Self-signed CA
#   - san-test-all-types.pem: Certificate with all supported SAN types
#   - san-test-dns-ip.pem: Certificate with DNS and IP SANs
#   - san-test-email-uri.pem: Certificate with email and URI SANs
#   - san-test-othername-upn.pem: Certificate with Microsoft UPN otherName
#   - san-test-dirname-rid.pem: Certificate with directoryName and registeredID
#
# SAN Types (RFC 5280 GeneralName):
#   0 = otherName (Microsoft UPN: OID 1.3.6.1.4.1.311.20.2.3)
#   1 = rfc822Name (email)
#   2 = dNSName
#   4 = directoryName
#   6 = uniformResourceIdentifier (URI)
#   7 = iPAddress (IPv4 and IPv6)
#   8 = registeredID

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Certificate validity (10 years)
DAYS=3650

# Output directory for SAN test certs
SAN_DIR="san-test"
mkdir -p "$SAN_DIR"

printf "Generating SAN test certificates in %s/\n" "$SAN_DIR"

# =============================================================================
# Generate CA key and self-signed certificate
# =============================================================================
printf "\n[1/7] Generating SAN test CA...\n"

openssl genrsa -out "$SAN_DIR/san-test-ca-key.pem" 2048

openssl req -x509 -new -nodes \
    -key "$SAN_DIR/san-test-ca-key.pem" \
    -sha256 -days $DAYS \
    -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Testing/CN=SAN Test CA" \
    -out "$SAN_DIR/san-test-ca-cert.pem"

printf "  Created: san-test-ca-key.pem, san-test-ca-cert.pem\n"

# =============================================================================
# Helper function to generate a certificate with SANs
# =============================================================================
generate_cert() {
    local name=$1
    local cn=$2
    local san_config=$3
    local extra_sections=$4

    printf "\n[%s] Generating %s...\n" "$5" "$name"

    # Generate key
    openssl genrsa -out "$SAN_DIR/${name}-key.pem" 2048

    # Create CSR
    openssl req -new \
        -key "$SAN_DIR/${name}-key.pem" \
        -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Testing/CN=${cn}" \
        -out "$SAN_DIR/${name}.csr"

    # Create extension config file
    cat > "$SAN_DIR/${name}-ext.cnf" << EOF
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[san_ext]
subjectAltName = ${san_config}
${extra_sections}
EOF

    # Sign with CA
    openssl x509 -req \
        -in "$SAN_DIR/${name}.csr" \
        -CA "$SAN_DIR/san-test-ca-cert.pem" \
        -CAkey "$SAN_DIR/san-test-ca-key.pem" \
        -CAcreateserial \
        -out "$SAN_DIR/${name}.pem" \
        -days $DAYS \
        -sha256 \
        -extfile "$SAN_DIR/${name}-ext.cnf" \
        -extensions san_ext

    # Also create DER format
    openssl x509 -in "$SAN_DIR/${name}.pem" -outform DER -out "$SAN_DIR/${name}.der"

    # Cleanup CSR and config
    rm -f "$SAN_DIR/${name}.csr" "$SAN_DIR/${name}-ext.cnf"

    printf "  Created: %s.pem, %s.der\n" "$name" "$name"
}

# =============================================================================
# Certificate 1: DNS and IP addresses (most common case)
# =============================================================================
generate_cert "san-test-dns-ip" "DNS and IP Test" \
    "DNS:localhost,DNS:example.com,DNS:*.wildcard.com,IP:127.0.0.1,IP:192.168.1.1,IP:::1,IP:fe80::1" \
    "" "2/7"

# =============================================================================
# Certificate 2: Email and URI
# =============================================================================
generate_cert "san-test-email-uri" "Email and URI Test" \
    "email:test@example.com,email:admin@wolfssl.com,URI:https://www.wolfssl.com,URI:ldap://ldap.example.com/cn=test" \
    "" "3/7"

# =============================================================================
# Certificate 3: Microsoft UPN otherName (for Active Directory)
# Microsoft UPN OID: 1.3.6.1.4.1.311.20.2.3
# =============================================================================
printf "\n[4/7] Generating san-test-othername-upn...\n"

# Generate key
openssl genrsa -out "$SAN_DIR/san-test-othername-upn-key.pem" 2048

# Create CSR
openssl req -new \
    -key "$SAN_DIR/san-test-othername-upn-key.pem" \
    -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Testing/CN=UPN Test User" \
    -out "$SAN_DIR/san-test-othername-upn.csr"

# Create extension config with otherName for UPN
# The format is: otherName:OID;encoding:value
# For UPN, OID is 1.3.6.1.4.1.311.20.2.3 and value is UTF8String
cat > "$SAN_DIR/san-test-othername-upn-ext.cnf" << 'EOF'
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[san_ext]
subjectAltName = @san_names

[san_names]
otherName.0 = 1.3.6.1.4.1.311.20.2.3;UTF8:testuser@example.com
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:admin@wolfssl.local
email = testuser@example.com
EOF

# Sign with CA
openssl x509 -req \
    -in "$SAN_DIR/san-test-othername-upn.csr" \
    -CA "$SAN_DIR/san-test-ca-cert.pem" \
    -CAkey "$SAN_DIR/san-test-ca-key.pem" \
    -CAcreateserial \
    -out "$SAN_DIR/san-test-othername-upn.pem" \
    -days $DAYS \
    -sha256 \
    -extfile "$SAN_DIR/san-test-othername-upn-ext.cnf" \
    -extensions san_ext

# Also create DER format
openssl x509 -in "$SAN_DIR/san-test-othername-upn.pem" -outform DER \
    -out "$SAN_DIR/san-test-othername-upn.der"

# Cleanup
rm -f "$SAN_DIR/san-test-othername-upn.csr" "$SAN_DIR/san-test-othername-upn-ext.cnf"

printf "  Created: san-test-othername-upn.pem, san-test-othername-upn.der\n"

# =============================================================================
# Certificate 4: directoryName and registeredID
# =============================================================================
printf "\n[5/7] Generating san-test-dirname-rid...\n"

# Generate key
openssl genrsa -out "$SAN_DIR/san-test-dirname-rid-key.pem" 2048

# Create CSR
openssl req -new \
    -key "$SAN_DIR/san-test-dirname-rid-key.pem" \
    -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Testing/CN=DirName RID Test" \
    -out "$SAN_DIR/san-test-dirname-rid.csr"

# Create extension config with directoryName and registeredID
cat > "$SAN_DIR/san-test-dirname-rid-ext.cnf" << 'EOF'
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[san_ext]
subjectAltName = @san_names

[san_names]
dirName.0 = dir_sect_1
dirName.1 = dir_sect_2
RID = 1.2.3.4.5.6.7.8.9

[dir_sect_1]
C = US
ST = California
L = San Francisco
O = Test Organization
CN = Directory Name Test 1

[dir_sect_2]
C = DE
O = German Organization
CN = Directory Name Test 2
EOF

# Sign with CA
openssl x509 -req \
    -in "$SAN_DIR/san-test-dirname-rid.csr" \
    -CA "$SAN_DIR/san-test-ca-cert.pem" \
    -CAkey "$SAN_DIR/san-test-ca-key.pem" \
    -CAcreateserial \
    -out "$SAN_DIR/san-test-dirname-rid.pem" \
    -days $DAYS \
    -sha256 \
    -extfile "$SAN_DIR/san-test-dirname-rid-ext.cnf" \
    -extensions san_ext

# Also create DER format
openssl x509 -in "$SAN_DIR/san-test-dirname-rid.pem" -outform DER \
    -out "$SAN_DIR/san-test-dirname-rid.der"

# Cleanup
rm -f "$SAN_DIR/san-test-dirname-rid.csr" "$SAN_DIR/san-test-dirname-rid-ext.cnf"

printf "  Created: san-test-dirname-rid.pem, san-test-dirname-rid.der\n"

# =============================================================================
# Certificate 5: ALL SAN types in one certificate (comprehensive test)
# =============================================================================
printf "\n[6/7] Generating san-test-all-types (comprehensive)...\n"

# Generate key
openssl genrsa -out "$SAN_DIR/san-test-all-types-key.pem" 2048

# Create CSR
openssl req -new \
    -key "$SAN_DIR/san-test-all-types-key.pem" \
    -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Testing/CN=All SAN Types Test" \
    -out "$SAN_DIR/san-test-all-types.csr"

# Create extension config with ALL SAN types
# Note: registeredID (type 8) is excluded as it can cause issues with some
# wolfSSL builds when parsing
cat > "$SAN_DIR/san-test-all-types-ext.cnf" << 'EOF'
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[san_ext]
subjectAltName = @san_names

[san_names]
# Type 0: otherName (Microsoft UPN)
otherName.0 = 1.3.6.1.4.1.311.20.2.3;UTF8:allsantypes@wolfssl.com

# Type 1: rfc822Name (email)
email.0 = test@example.com
email.1 = admin@wolfssl.com

# Type 2: dNSName
DNS.0 = localhost
DNS.1 = www.example.com
DNS.2 = *.wildcard.example.com

# Type 4: directoryName
dirName.0 = dir_sect

# Type 6: uniformResourceIdentifier
URI.0 = https://www.wolfssl.com
URI.1 = ldap://ldap.example.com/cn=test

# Type 7: iPAddress (IPv4 and IPv6)
IP.0 = 127.0.0.1
IP.1 = 192.168.1.100
IP.2 = ::1
IP.3 = fe80::1234:5678:abcd:ef00

# Note: registeredID (type 8) excluded - can cause issues with wolfSSL parsing

[dir_sect]
C = US
ST = Montana
L = Bozeman
O = wolfSSL Inc.
OU = Engineering
CN = Directory Name Entry
EOF

# Sign with CA
openssl x509 -req \
    -in "$SAN_DIR/san-test-all-types.csr" \
    -CA "$SAN_DIR/san-test-ca-cert.pem" \
    -CAkey "$SAN_DIR/san-test-ca-key.pem" \
    -CAcreateserial \
    -out "$SAN_DIR/san-test-all-types.pem" \
    -days $DAYS \
    -sha256 \
    -extfile "$SAN_DIR/san-test-all-types-ext.cnf" \
    -extensions san_ext

# Also create DER format
openssl x509 -in "$SAN_DIR/san-test-all-types.pem" -outform DER \
    -out "$SAN_DIR/san-test-all-types.der"

# Cleanup
rm -f "$SAN_DIR/san-test-all-types.csr" "$SAN_DIR/san-test-all-types-ext.cnf"

printf "  Created: san-test-all-types.pem, san-test-all-types.der\n"

# =============================================================================
# Cleanup and summary
# =============================================================================
printf "\n[7/7] Cleanup and verification...\n"

# Remove CA serial file
rm -f "$SAN_DIR/san-test-ca-cert.srl"

# Remove all private keys except CA (tests only need certs)
# Uncomment if you want to keep keys minimal:
# rm -f "$SAN_DIR/san-test-dns-ip-key.pem"
# rm -f "$SAN_DIR/san-test-email-uri-key.pem"
# rm -f "$SAN_DIR/san-test-othername-upn-key.pem"
# rm -f "$SAN_DIR/san-test-dirname-rid-key.pem"
# rm -f "$SAN_DIR/san-test-all-types-key.pem"

printf "\n========================================\n"
printf "SAN Test Certificate Generation Complete\n"
printf "========================================\n"
printf "\nGenerated files in %s/:\n" "$SAN_DIR"
ls -la "$SAN_DIR"/*.pem "$SAN_DIR"/*.der 2>/dev/null | awk '{print "  " $NF}'

printf "\nVerifying SAN extensions in generated certificates:\n"

printf "\n--- san-test-dns-ip.pem ---\n"
openssl x509 -in "$SAN_DIR/san-test-dns-ip.pem" -noout -text | grep -A20 "Subject Alternative Name" | head -10

printf "\n--- san-test-email-uri.pem ---\n"
openssl x509 -in "$SAN_DIR/san-test-email-uri.pem" -noout -text | grep -A20 "Subject Alternative Name" | head -10

printf "\n--- san-test-othername-upn.pem ---\n"
openssl x509 -in "$SAN_DIR/san-test-othername-upn.pem" -noout -text | grep -A20 "Subject Alternative Name" | head -10

printf "\n--- san-test-dirname-rid.pem ---\n"
openssl x509 -in "$SAN_DIR/san-test-dirname-rid.pem" -noout -text | grep -A20 "Subject Alternative Name" | head -15

printf "\n--- san-test-all-types.pem (comprehensive) ---\n"
openssl x509 -in "$SAN_DIR/san-test-all-types.pem" -noout -text | grep -A50 "Subject Alternative Name" | head -30

printf "\nDone! Certificates are ready for testing WolfSSLAltName functionality.\n"

