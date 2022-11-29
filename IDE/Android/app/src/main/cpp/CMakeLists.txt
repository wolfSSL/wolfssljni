# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Add preprocessor defines to CFLAGS
add_definitions(-DHAVE_FFDHE_2048 -DWOLFSSL_TLS13 -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES
        -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_AESGCM
        -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_HKDF -DNO_DSA -DHAVE_ECC -DTFM_ECC256
        -DECC_SHAMIR -DWC_RSA_PSS -DWOLFSSL_BASE64_ENCODE -DNO_RC4
        -DWOLFSSL_SHA224 -DWOLFSSL_SHA3 -DHAVE_POLY1305 -DHAVE_ONE_TIME_AUTH -DHAVE_CHACHA
        -DHAVE_HASHDRBG -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_EXTENDED_MASTER
        -DHAVE_SNI -DHAVE_ALPN -DWOLFSSL_JNI -DOPENSSL_EXTRA -DOPENSSL_ALL
        -DHAVE_EX_DATA -DHAVE_CRL -DHAVE_OCSP -DHAVE_CRL_MONITOR -DPERSIST_SESSION_CACHE
        -DPERSIST_CERT_CACHE -DATOMIC_USER -DHAVE_PK_CALLBACKS -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN
        -DHAVE_ENCRYPT_THEN_MAC -DNO_MD4 -DWOLFSSL_ENCRYPTED_KEYS -DUSE_FAST_MATH -DNO_DES3
        -DKEEP_PEER_CERT -DSESSION_CERTS -DHAVE_SESSION_TICKET -DSIZEOF_LONG=4 -DSIZEOF_LONG_LONG=8
        -DTFM_NO_ASM)

# set wolfSSL JNI location as environment variable, change if needed
set(wolfssljni_DIR ${CMAKE_SOURCE_DIR}/../../../../../../)
set(wolfssl_DIR    ${CMAKE_SOURCE_DIR}/wolfssl/)


# Add header directories to include paths
include_directories(
    ${wolfssl_DIR}
    ${wolfssljni_DIR}/native
)

# Add wolfSSL library source files, to be compiled as SHARED library
add_library(wolfssl SHARED
        ${wolfssl_DIR}/wolfcrypt/src/aes.c
        ${wolfssl_DIR}/wolfcrypt/src/arc4.c
        ${wolfssl_DIR}/wolfcrypt/src/asm.c
        ${wolfssl_DIR}/wolfcrypt/src/asn.c
        ${wolfssl_DIR}/wolfcrypt/src/blake2b.c
        ${wolfssl_DIR}/wolfcrypt/src/blake2s.c
        ${wolfssl_DIR}/wolfcrypt/src/camellia.c
        ${wolfssl_DIR}/wolfcrypt/src/chacha.c
        ${wolfssl_DIR}/wolfcrypt/src/chacha20_poly1305.c
        ${wolfssl_DIR}/wolfcrypt/src/cmac.c
        ${wolfssl_DIR}/wolfcrypt/src/coding.c
        ${wolfssl_DIR}/wolfcrypt/src/compress.c
        ${wolfssl_DIR}/wolfcrypt/src/cpuid.c
        ${wolfssl_DIR}/wolfcrypt/src/cryptocb.c
        ${wolfssl_DIR}/wolfcrypt/src/curve25519.c
        ${wolfssl_DIR}/wolfcrypt/src/curve448.c
        ${wolfssl_DIR}/wolfcrypt/src/des3.c
        ${wolfssl_DIR}/wolfcrypt/src/dh.c
        ${wolfssl_DIR}/wolfcrypt/src/dsa.c
        ${wolfssl_DIR}/wolfcrypt/src/ecc.c
        ${wolfssl_DIR}/wolfcrypt/src/ecc_fp.c
        ${wolfssl_DIR}/wolfcrypt/src/eccsi.c
        ${wolfssl_DIR}/wolfcrypt/src/ed25519.c
        ${wolfssl_DIR}/wolfcrypt/src/ed448.c
        ${wolfssl_DIR}/wolfcrypt/src/error.c
        ${wolfssl_DIR}/wolfcrypt/src/fe_448.c
        ${wolfssl_DIR}/wolfcrypt/src/fe_low_mem.c
        ${wolfssl_DIR}/wolfcrypt/src/fe_operations.c
        ${wolfssl_DIR}/wolfcrypt/src/ge_448.c
        ${wolfssl_DIR}/wolfcrypt/src/ge_low_mem.c
        ${wolfssl_DIR}/wolfcrypt/src/ge_operations.c
        ${wolfssl_DIR}/wolfcrypt/src/hash.c
        ${wolfssl_DIR}/wolfcrypt/src/hmac.c
        ${wolfssl_DIR}/wolfcrypt/src/integer.c
        ${wolfssl_DIR}/wolfcrypt/src/kdf.c
        ${wolfssl_DIR}/wolfcrypt/src/logging.c
        ${wolfssl_DIR}/wolfcrypt/src/md2.c
        ${wolfssl_DIR}/wolfcrypt/src/md4.c
        ${wolfssl_DIR}/wolfcrypt/src/md5.c
        ${wolfssl_DIR}/wolfcrypt/src/memory.c
        ${wolfssl_DIR}/wolfcrypt/src/pkcs12.c
        ${wolfssl_DIR}/wolfcrypt/src/pkcs7.c
        ${wolfssl_DIR}/wolfcrypt/src/poly1305.c
        ${wolfssl_DIR}/wolfcrypt/src/pwdbased.c
        ${wolfssl_DIR}/wolfcrypt/src/random.c
        ${wolfssl_DIR}/wolfcrypt/src/rc2.c
        ${wolfssl_DIR}/wolfcrypt/src/ripemd.c
        ${wolfssl_DIR}/wolfcrypt/src/rsa.c
        ${wolfssl_DIR}/wolfcrypt/src/sakke.c
        ${wolfssl_DIR}/wolfcrypt/src/sha256.c
        ${wolfssl_DIR}/wolfcrypt/src/sha3.c
        ${wolfssl_DIR}/wolfcrypt/src/sha512.c
        ${wolfssl_DIR}/wolfcrypt/src/sha.c
        ${wolfssl_DIR}/wolfcrypt/src/signature.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_arm32.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_arm64.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_armthumb.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_c32.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_c64.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_cortexm.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_dsp32.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_int.c
        ${wolfssl_DIR}/wolfcrypt/src/sp_x86_64.c
        ${wolfssl_DIR}/wolfcrypt/src/srp.c
        ${wolfssl_DIR}/wolfcrypt/src/tfm.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_dsp.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_encrypt.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_pkcs11.c
        ${wolfssl_DIR}/wolfcrypt/src/wc_port.c
        ${wolfssl_DIR}/wolfcrypt/src/wolfevent.c
        ${wolfssl_DIR}/wolfcrypt/src/wolfmath.c
        ${wolfssl_DIR}/src/crl.c
        ${wolfssl_DIR}/src/dtls13.c
        ${wolfssl_DIR}/src/dtls.c
        ${wolfssl_DIR}/src/internal.c
        ${wolfssl_DIR}/src/keys.c
        ${wolfssl_DIR}/src/ocsp.c
        ${wolfssl_DIR}/src/sniffer.c
        ${wolfssl_DIR}/src/ssl.c
        ${wolfssl_DIR}/src/tls13.c
        ${wolfssl_DIR}/src/tls.c
        ${wolfssl_DIR}/src/wolfio.c
        )

# set_target_properties(wolfssl PROPERTIES LIBRARY_OUTPUT_DIRECTORY
# ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# Add wolfSSL JNI library native source files, to be compiled as SHARED library
# wolfSSL JNI Java files are tied into build in Module build.gradle file
add_library(wolfssljni SHARED
        ${wolfssljni_DIR}/native/com_wolfssl_wolfcrypt_ECC.c
        ${wolfssljni_DIR}/native/com_wolfssl_wolfcrypt_EccKey.c
        ${wolfssljni_DIR}/native/com_wolfssl_wolfcrypt_RSA.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSL.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLCertificate.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLCertManager.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLContext.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLSession.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLX509StoreCtx.c
        )

# set_target_properties(wolfssljni PROPERTIES LIBRARY_OUTPUT_DIRECTORY
# ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# Include libraries needed for wolfSSL and wolfSSL JNI libs
target_link_libraries(wolfssljni
        wolfssl
        android
        log)
