#!/usr/bin/env bash
#
# update-keystore-pqc.sh
#
# Generates ML-DSA (FIPS 204) keystores for wolfJSSE PQC tests, in both
# JKS and PKCS12 formats. PKCS12 is the JDK 24+ default keystore type;
# JKS is included for backward-compatibility coverage.
#
# Why this script exists:
#   - JDK 24+ added ML-DSA via JEP 497 (KeyFactory, KeyPairGenerator,
#     Signature, KeyTool support). Prior JDK versions cannot read ML-DSA
#     private keys via standard JCE.
#   - OpenSSL 3.5+ and JDK 24+ disagree on the ML-DSA private key encoding
#     (seed-only vs expanded form). Cross-toolchain JKS conversion is
#     unreliable.
#   - Therefore, the simplest portable path is to use JDK 24+ keytool
#     to generate self-signed ML-DSA certs directly into the keystore,
#     no openssl involvement on the keystore side.
#
# Requirements:
#   - JDK 24 or newer in PATH, OR JAVA_HOME pointing at a JDK 24+ install.
#
# Output, per ML-DSA level (44, 65, 87) and per format (jks, p12):
#   server-mldsaN.{jks,p12}  -- private key + server cert chain
#   client-mldsaN.{jks,p12}  -- private key + client cert chain
#   ca-mldsaN.{jks,p12}      -- root cert only (truststore for both sides)
#
# The client and server entity certs are signed by the same root, so a
# single ca-mldsaN.{jks,p12} truststore is sufficient for mutual auth.
#
# Tests that consume these files (WolfSSLPQCAuthKeyStoreTest) skip cleanly
# on JDK < 24 via a runtime KeyFactory.getInstance("ML-DSA") check.

set -euo pipefail

PASSWD="wolfSSL test"
OUT_DIR="$(dirname "$0")"

KT="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"

# One private scratch dir for all keytool work. mktemp -d gives it an
# unpredictable name and mode 0700. The trap removes it on every exit.
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wolfssl-pqc.XXXXXXXX")"
trap 'rm -rf -- "$WORK_ROOT"' EXIT

# Verify JDK 24+
if ! "$KT" -genkeypair -keyalg ML-DSA -alias _probe \
        -keystore "$WORK_ROOT/probe.jks" -storepass "$PASSWD" \
        -dname "CN=probe" >/dev/null 2>&1; then
    echo "ERROR: keytool does not support ML-DSA. Need JDK 24+." >&2
    echo "  Tried: $KT" >&2
    "$KT" -version 2>&1 || true
    exit 1
fi

# Generate one entity keystore (server or client) signed by the supplied
# root. Helper used by gen_keystore() so both roles share one root.
gen_entity_keystore() {
    local level="$1"
    local storetype="$2"
    local ext="$3"
    local role="$4"           # "server" or "client"
    local root_ks="$5"        # path to the root keystore (in $work)
    local work="$6"           # scratch directory
    local alg="ML-DSA-${level}"
    local entity_ks="${OUT_DIR}/${role}-mldsa${level}.${ext}"
    local alias="${role}-mldsa${level}"

    rm -f "$entity_ks"

    # Server cert gets a SAN (dns:example.com, ip:127.0.0.1); the client
    # cert does not need one. Both certs share the same root.
    local entity_san_args=()
    if [ "$role" = "server" ]; then
        entity_san_args=(-ext "san=dns:example.com,ip:127.0.0.1")
    fi

    # 1. Entity keypair (initially self-signed in its own keystore)
    "$KT" -genkeypair -keyalg "$alg" \
        -alias "$alias" \
        -keystore "$entity_ks" -storepass "$PASSWD" \
        -keypass "$PASSWD" -storetype "$storetype" \
        -dname "CN=ML-DSA-${level} ${role}, O=wolfSSL, C=US" \
        ${entity_san_args[@]+"${entity_san_args[@]}"} -validity 3650

    # 2. CSR from the entity keystore
    "$KT" -certreq -alias "$alias" \
        -keystore "$entity_ks" -storepass "$PASSWD" \
        -file "$work/${role}.csr"

    # 3. Sign the CSR with the root CA
    "$KT" -gencert -alias "root-mldsa${level}" \
        -keystore "$root_ks" -storepass "$PASSWD" \
        -infile "$work/${role}.csr" -outfile "$work/${role}.crt" \
        ${entity_san_args[@]+"${entity_san_args[@]}"} -validity 3650

    # 4. Import root into the entity keystore so the next import can chain
    "$KT" -importcert -noprompt -trustcacerts \
        -alias "root-mldsa${level}" \
        -keystore "$entity_ks" -storepass "$PASSWD" \
        -storetype "$storetype" \
        -file "$work/root.crt"

    # 5. Replace the self-signed entity cert with the CA-signed one,
    #    forming a real chain inside the keystore
    "$KT" -importcert -noprompt -alias "$alias" \
        -keystore "$entity_ks" -storepass "$PASSWD" \
        -storetype "$storetype" \
        -file "$work/${role}.crt"
}

# Generate proper cert chain per ML-DSA level + storetype: a CA keypair
# signs server and client entity certs. Output per (level, storetype):
#   server-mldsaN.<ext>   -- private key + server cert chain (server+root)
#   client-mldsaN.<ext>   -- private key + client cert chain (client+root)
#   ca-mldsaN.<ext>       -- root cert only (truststore for both sides)
gen_keystore() {
    local level="$1"
    local storetype="$2"   # JKS or PKCS12
    local ext="$3"         # jks or p12
    local alg="ML-DSA-${level}"
    local ca_ks="${OUT_DIR}/ca-mldsa${level}.${ext}"
    local work="${WORK_ROOT}/mldsa${level}_${ext}"
    local root_ks="${work}/root.${ext}"

    echo "=== Generating ML-DSA-${level} (${storetype}) cert chain ==="

    rm -f "$ca_ks"
    mkdir "$work"

    # 1. Root CA self-signed (kept in $work; never shipped)
    "$KT" -genkeypair -keyalg "$alg" \
        -alias "root-mldsa${level}" \
        -keystore "$root_ks" -storepass "$PASSWD" \
        -keypass "$PASSWD" -storetype "$storetype" \
        -dname "CN=ML-DSA-${level} Root CA, O=wolfSSL, C=US" \
        -ext "bc:c=ca:true" -validity 3650

    # 2. Export the root cert (used by entity keystores and the truststore)
    "$KT" -exportcert -alias "root-mldsa${level}" \
        -keystore "$root_ks" -storepass "$PASSWD" \
        -file "$work/root.crt"

    # 3. Server entity keystore signed by root
    gen_entity_keystore "$level" "$storetype" "$ext" "server" \
        "$root_ks" "$work"

    # 4. Client entity keystore signed by the same root
    gen_entity_keystore "$level" "$storetype" "$ext" "client" \
        "$root_ks" "$work"

    # 5. Truststore (root cert only) -- valid for both server- and
    #    client-side verification since both entity certs share this root
    "$KT" -importcert -noprompt -trustcacerts \
        -alias "root-mldsa${level}" \
        -keystore "$ca_ks" -storepass "$PASSWD" \
        -storetype "$storetype" \
        -file "$work/root.crt"

    rm -rf "$work"
}

# Generate (level, storetype) cross product. JKS first for backward-compat
# coverage; PKCS12 second since it's the JDK 24+ default keystore type.
for level in 44 65 87; do
    gen_keystore "$level" "JKS"    "jks"
    gen_keystore "$level" "PKCS12" "p12"
done

echo ""
echo "=== Done. Generated keystore files: ==="
ls -1 "$OUT_DIR"/server-mldsa*.{jks,p12} \
      "$OUT_DIR"/client-mldsa*.{jks,p12} \
      "$OUT_DIR"/ca-mldsa*.{jks,p12} 2>/dev/null
