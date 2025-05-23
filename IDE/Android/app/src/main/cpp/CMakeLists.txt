# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.4.1)

# Define project as both C and ASM for cases for SP has assembly enabled
project("wolfssljni-gradle" C ASM)

# set wolfSSL JNI location as environment variable, change if needed
set(wolfssljni_DIR ${CMAKE_SOURCE_DIR}/../../../../../../)
set(wolfssl_DIR    ${CMAKE_SOURCE_DIR}/wolfssl/)

# set warnings as errors, used in this example project but may be different
# in production apps/environments.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

# ------------------------- wolfSSL Normal vs. FIPS Ready Selection --------------------------------
# Select if wolfSSL is normal ("normal") or FIPS Ready ("fipsready")
# wolfSSL FIPS Ready is available for download on the wolfssl.com download page. For more
# information on wolfSSL FIPS Ready see: https://www.wolfssl.com/license/fips/
#
# FIPS Ready requires different preprocessor flags, files, and a specific file ordering
# as set up below.
set(WOLFSSL_PKG_TYPE "normal")

# -------------------------------- Math Library Selection ------------------------------------------
# wolfCrypt math library selection, used to switch on below. Should be one of:
#     fastmath
#     spmath
set(WOLFSSL_MATH_LIB "spmath")

# Add header directories to include paths
include_directories(
        ${wolfssl_DIR}
        ${wolfssljni_DIR}/native
)

# ------------------------------- Preprocessor Defines ---------------------------------------------

if ("${WOLFSSL_PKG_TYPE}" MATCHES "normal")
        # Add preprocessor defines to CFLAGS, these match those placed into
        # wolfssl/options.h by configure if using: "./configure --enable-jni".
        # This list may be configurable depending on use case and desired optimizations.
        add_definitions(-DWC_RSA_BLINDING -DWOLFSSL_SHA224 -DWOLFSSL_SHA384
                -DWOLFSSL_SHA512 -DHAVE_HKDF -DNO_DSA -DHAVE_ECC
                -DECC_SHAMIR -DWC_RSA_PSS -DWOLFSSL_BASE64_ENCODE
                -DWOLFSSL_SHA3 -DHAVE_POLY1305 -DHAVE_CHACHA -DHAVE_HASHDRBG
                -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_FFDHE_2048
                -DWOLFSSL_TLS13 -DHAVE_EXTENDED_MASTER -DWOLFSSL_JNI
                -DHAVE_EX_DATA -DWOLFSSL_DTLS -DOPENSSL_EXTRA -DOPENSSL_ALL
                -DHAVE_CRL -DHAVE_OCSP -DHAVE_CRL_MONITOR
                -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER
                -DHAVE_PK_CALLBACKS -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN
                -DWOLFSSL_CERT_REQ -DHAVE_SNI -DHAVE_ALPN -DNO_RC4
                -DHAVE_ENCRYPT_THEN_MAC -DNO_MD4 -DWOLFSSL_ENCRYPTED_KEYS
                -DHAVE_DH_DEFAULT_PARAMS -DNO_ERROR_QUEUE -DWOLFSSL_EITHER_SIDE
                -DWC_RSA_NO_PADDING -DWC_RSA_PSS -DWOLFSSL_PSS_LONG_SALT
                -DWOLFSSL_TICKET_HAVE_ID -DWOLFSSL_ERROR_CODE_OPENSSL
                -DWOLFSSL_ALWAYS_VERIFY_CB -DWOLFSSL_VERIFY_CB_ALL_CERTS
                -DWOLFSSL_EXTRA_ALERTS -DHAVE_EXT_CACHE
                -DWOLFSSL_FORCE_CACHE_ON_TICKET -DWOLFSSL_AKID_NAME -DHAVE_CTS
                -DNO_DES3 -DGCM_TABLE_4BIT -DTFM_TIMING_RESISTANT
                -DECC_TIMING_RESISTANT -DHAVE_AESGCM -DSIZEOF_LONG=4
                -DSIZEOF_LONG_LONG=8 -DWOLFSSL_CUSTOM_CONFIG

                # For gethostbyname()
                -DHAVE_NETDB_H

                # Defines added for debugging. These can be removed if debug logging is not needed
                # and will increase performance and reduce library footprint size if removed.
                #-DDEBUG_WOLFSSL -DWOLFSSL_ANDROID_DEBUG

                # Defines added for wolfCrypt test and benchmark only, may not be needed for your
                # own application.
                # Add -DNO_FILESYSTEM to disable file system use for wolfCrypt test, but make sure
                # to remove this define in production applications as filesystem access is required
                # for wolfJSSE use.
                -DUSE_CERT_BUFFERS_2048 -DUSE_CERT_BUFFERS_256
                -DNO_WRITE_TEMP_FILES -DNO_MAIN_DRIVER
        )

elseif("${WOLFSSL_PKG_TYPE}" MATCHES "fipsready")
        # The wolfCrypt FIPS In Core Integrity checksum will vary with compiler
        # versions, runtime library versions, target hardware, and build type.
        # Anytime the module is shifted up or down in memory or loaded from a new
        # memory location the hash will change. This is expected during normal
        # development cycles but should be stable in a production deployment.
        # The verifyCore[] hash can be manually updated in
        # 'wolfcrypt/src/fips_test.c' and the app recompiled. Or, the define
        # WOLFCRYPT_FIPS_CORE_HASH_VALUE can be set below, which is helpful
        # for Android Studio, which builds for all these architectures in the same
        # build.
        #
        # The hash values below are only for reference and will need to
        # be updated to match your build. To update this value:
        #
        #  1. Build and install your app which contains wolfCrypt FIPS
        #  2. Run your app on each architecture, looking at the logcat output
        #     to see the expected verifyCore[] hash value.
        #  3. Copy the expected hash value from logcat to the proper architecture
        #     section below.
        #  4. Re-build your application now that the expected hash value has
        #     been set.
        #  5. Re-install and re-run your application on each architecture to
        #     confirm the hash is stable and application runs as expected.
        #
        # NOTE: If using wolfSSL FIPS Ready or FIPS proper with this sample
        # application and run into the scenario where the verifyCore[] hash output
        # at runtime is empty, consider checking/increasing the size of the
        # MAX_FIPS_DATA_SZ define in 'wolfcrypt/src/fips_test.c'.

        if("${ANDROID_ABI}" MATCHES "arm64-v8a")
                # https://developer.android.com/ndk/guides/abis#arm64-v8a
                add_definitions(-DWOLFCRYPT_FIPS_CORE_HASH_VALUE=DF2FF40654C405467072356FBA6C02A88F17E79B08A1A8F3A887C0F6AB4E4650)
        elseif("${ANDROID_ABI}" MATCHES "armeabi-v7a")
                # https://developer.android.com/ndk/guides/abis#v7a
                add_definitions(-DWOLFCRYPT_FIPS_CORE_HASH_VALUE=DF2FF40654C405467072356FBA6C02A88F17E79B08A1A8F3A887C0F6AB4E4650)
        elseif("${ANDROID_ABI}" MATCHES "x86_64")
                # https://developer.android.com/ndk/guides/abis#86-64
                add_definitions(-DWOLFCRYPT_FIPS_CORE_HASH_VALUE=DF2FF40654C405467072356FBA6C02A88F17E79B08A1A8F3A887C0F6AB4E4650)
        elseif("${ANDROID_ABI}" MATCHES "x86")
                # https://developer.android.com/ndk/guides/abis#x86
                add_definitions(-DWOLFCRYPT_FIPS_CORE_HASH_VALUE=DF2FF40654C405467072356FBA6C02A88F17E79B08A1A8F3A887C0F6AB4E4650)
        endif()

        # Add preprocessor defines to CFLAGS, these match those placed into
        # wolfssl/options.h by configure if using the following configure on a Unix/Linux
        # platform with a wolfSSL FIPS Ready GPLv3 bundle:
        #
        # ./configure --enable-fips=ready --enable-jni
        #
        # This list may be configurable depending on use case and desired
        # optimizations, being careful not to break FIPS compatibility if targeting
        # FIPS proper in the future. Please contact support@wolfssl.com for assistance
        # properly compiling for use with wolfCrypt FIPS variants.
        add_definitions(
                -DWOLFSSL_FIPS_READY -DHAVE_FIPS -DHAVE_FIPS_VERSION=7
                -DHAVE_FIPS_VERSION_MAJOR=7 -DHAVE_FIPS_VERSION_MINOR=0
                -DHAVE_FIPS_VERSION_PATCH=0 -DWC_RNG_SEED_CB -DHAVE_THREAD_LS

                -DWOLFSSL_WOLFSSH -DNO_DO178 -DHAVE_REPRODUCIBLE_BUILD -DWC_NO_ASYNC_THREADING
                -DNO_OLD_TLS -DWOLFSSL_TLS13 -DHAVE_TLS_EXTENSIONS -DHAVE_SNI
                -DHAVE_KEYING_MATERIAL -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES
                -DHAVE_EXTENDED_MASTER -DHAVE_ENCRYPT_THEN_MAC -DWOLFSSL_JNI -DHAVE_EX_DATA
                -DKEEP_PEER_CERT -DWOLFSSL_ALWAYS_VERIFY_CB -DWOLFSSL_DTLS -DOPENSSL_EXTRA
                -DOPENSSL_ALL -DWOLFSSL_ERROR_CODE_OPENSSL -DHAVE_CRL -DHAVE_CRL_MONITOR
                -DHAVE_OCSP -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER
                -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_REQ -DWOLFSSL_KEY_GEN
                -DHAVE_ALPN -DWOLFSSL_ALT_CERT_CHAINS -DSESSION_CERTS -DWOLFSSL_ENCRYPTED_KEYS
                -DWOLFSSL_SYS_CA_CERTS -DWOLFSSL_ALT_NAMES -DWOLFSSL_EITHER_SIDE
                -DWOLFSSL_TICKET_HAVE_ID -DWOLFSSL_CERT_NAME_ALL
                -DHAVE_SERVER_RENEGOTIATION_INFO -DWOLFSSL_ASN_TEMPLATE -DWOLFSSL_ASN_PRINT
                -DWOLFSSL_BASE64_ENCODE -DERROR_QUEUE_PER_THREAD -DNO_ERROR_QUEUE
                -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWOLFSSL_USE_ALIGN
                -DWOLFSSL_PUBLIC_MP

                -DWC_RSA_BLINDING -DWC_RSA_PSS -DWOLFSSL_PSS_LONG_SALT -DWC_RSA_NO_PADDING

                -DHAVE_ECC -DTFM_ECC256 -DECC_SHAMIR -DECC_MIN_KEY_SZ=192 -DHAVE_ECC_CDH
                -DECC_USER_CURVES -DHAVE_ECC192 -DHAVE_ECC224 -DHAVE_ECC256 -DHAVE_ECC384
                -DHAVE_ECC521 -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_VALIDATE_ECC_IMPORT
                -DWOLFSSL_VALIDATE_ECC_KEYGEN

                -DWOLFSSL_VALIDATE_FFC_IMPORT -DHAVE_FFDHE_Q -DHAVE_FFDHE_2048
                -DHAVE_FFDHE_3072 -DHAVE_FFDHE_4096 -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192
                -DHAVE_DH_DEFAULT_PARAMS

                -DHAVE_HKDF -DHAVE_PBKDF2 -DHAVE_HASHDRBG -DWC_SRTP_KDF -DWOLFSSL_SRTP

                -DHAVE_AESGCM -DGCM_TABLE_4BIT -DWOLFSSL_AESGCM_STREAM -DHAVE_AESCCM
                -DWOLFSSL_AES_COUNTER -DWOLFSSL_CMAC -DWOLFSSL_AES_OFB -DWOLFSSL_AES_CFB
                -DWOLFSSL_AES_XTS -DWOLFSSL_AESXTS_STREAM -DWOLFSSL_AES_DIRECT
                -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP -DWOLFSSL_AES_XTS -DHAVE_AES_KEYWRAP

                -DHAVE_ED25519 -DHAVE_ED25519_KEY_IMPORT -DHAVE_ED448 -DHAVE_ED448_KEY_IMPORT
                -DWOLFSSL_ED448_STREAMING_VERIFY

                -DHAVE_CURVE25519 -DHAVE_CURVE448

                -DWOLFSSL_SHA224 -DWOLFSSL_SHA384 -DWOLFSSL_SHA512 -DWOLFSSL_NOSHA512_224
                -DWOLFSSL_NOSHA512_256 -DWOLFSSL_SHA3 -DWOLFSSL_SHAKE128 -DWOLFSSL_SHAKE256

                -DNO_DSA -DNO_RC4 -DNO_MD4 -DNO_DES3 -DNO_DES3_TLS_SUITES

                -DSIZEOF_LONG=4 -DSIZEOF_LONG_LONG=8 -DWOLFSSL_CUSTOM_CONFIG

                # For gethostbyname()
                -DHAVE_NETDB_H

                # Enable below options for wolfSSL debug logging
                #-DDEBUG_WOLFSSL -DWOLFSSL_ANDROID_DEBUG

                # Below options are added only for wolfCrypt test and benchmark applications.
                # These can be left off / removed when integrating into a real-world application.
                # Add -DNO_FILESYSTEM to disable file system use for wolfCrypt test, but make sure
                # to remove this define in production applications as filesystem access is required
                # for wolfJSSE use.
                -DUSE_CERT_BUFFERS_2048 -DUSE_CERT_BUFFERS_256
                -DNO_WRITE_TEMP_FILES -DNO_MAIN_DRIVER
        )
endif()

if ("$WOLFSSL_MATH_LIB" MATCHES "fastmath")
        # Use fastmath library
        add_definitions(-DUSE_FAST_MATH -DTFM_ECC256 -DTFM_NO_ASM)

elseif("${WOLFSSL_MATH_LIB}" MATCHES "spmath")
        # Use SP math Library
        add_definitions(
                -DWOLFSSL_HAVE_SP_RSA -DWOLFSSL_SP_4096
                -DWOLFSSL_HAVE_SP_DH
                -DWOLFSSL_HAVE_SP_ECC -DWOLFSSL_SP_384 -DWOLFSSL_SP_521
                -DWOLFSSL_SP_LARGE_CODE
                -DFP_MAX_BITS=16384 -DSP_INT_BITS=8192)

        # SP Math architecture-specific settings (ex: assembly optimizations)
        if("${ANDROID_ABI}" MATCHES "arm64-v8a")
                # Using ASM for SP, need to use WOLFSSL_SP_MATH instead of WOLFSSL_SP_MATH_ALL
                add_definitions(-DWOLFSSL_SP_MATH)
                add_definitions(-DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM64 -DWOLFSSL_SP_ARM64_ASM -DHAVE___UINT128_T)
        elseif("${ANDROID_ABI}" MATCHES "armeabi-v7a")
                # Add SP optimizations for ARMv7 here when available.
                # Not using ASM, need to use WOLFSSL_SP_MATH_ALL for SW-only implementation
                add_definitions(-DWOLFSSL_SP_MATH_ALL)
        elseif("${ANDROID_ABI}" MATCHES "x86_64")
                add_definitions(-DWOLFSSL_SP_MATH_ALL)
                add_definitions(-DWOLFSSL_SP_ASM -DWOLFSSL_SP_X86_64 -DWOLFSSL_SP_X86_64_ASM -DHAVE___UINT128_T)
                list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_x86_64_asm.S)
        elseif("${ANDROID_ABI}" MATCHES "x86")
                # Add SP optimizations for X86 here when available.
                # Not using ASM, need to use WOLFSSL_SP_MATH_ALL for SW-only implementation
                add_definitions(-DWOLFSSL_SP_MATH_ALL)
        else()
                # Not using ASM, need to use WOLFSSL_SP_MATH_ALL for SW-only implementation
                add_definitions(-DWOLFSSL_SP_MATH_ALL)
        endif()
endif()

# --------------------------- wolfSSL and wolfCrypt Source Files -----------------------------------
# Add TLS sources to TLS_SOURCES list and remove files that are included inline by other files
aux_source_directory(${wolfssl_DIR}/src TLS_SOURCES)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/bio.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/conf.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/pk.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_bn.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_asn1.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_certman.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_crypto.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_load.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_misc.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_p7p12.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/ssl_sess.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/x509.c)
list(REMOVE_ITEM TLS_SOURCES ${wolfssl_DIR}/src/x509_str.c)

if ("${WOLFSSL_PKG_TYPE}" MATCHES "normal")
        # Add crypto sources to CRYPTO_SOURCES, remove files that are included inline by other files
        aux_source_directory(${wolfssl_DIR}/wolfcrypt/src CRYPTO_SOURCES)
        list(REMOVE_ITEM CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/evp.c)
        list(REMOVE_ITEM CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/misc.c)

elseif("${WOLFSSL_PKG_TYPE}" MATCHES "fipsready")
        # FIPS Ready needs to explicitly order files for in-core integrity check to work properly.
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wolfcrypt_first.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/hmac.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/random.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/kdf.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/rsa.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/ecc.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/aes.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sha256.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sha.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sha512.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sha3.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/dh.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/cmac.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/curve448.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/ed448.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/curve25519.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/ed25519.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/pwdbased.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/fips.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/fips_test.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wolfcrypt_last.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/hash.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/cpuid.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/logging.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_port.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/error.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_encrypt.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/signature.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_arm32.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_arm64.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_armthumb.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_c32.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_c64.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_cortexm.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_dsp32.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_int.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/sp_x86_64.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wolfmath.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/memory.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/asn.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/coding.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/md5.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/pwdbased.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/pkcs12.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/tfm.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_lms.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_lms_impl.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_xmss.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/wc_xmss_impl.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/fe_operations.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/ge_operations.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/fe_448.c)
        list(APPEND CRYPTO_SOURCES ${wolfssl_DIR}/wolfcrypt/src/ge_448.c)
endif()

# wolfSSL will be compiled as a SHARED library
add_library(wolfssl SHARED
        ${CRYPTO_SOURCES}
        ${TLS_SOURCES}
)

# set_target_properties(wolfssl PROPERTIES LIBRARY_OUTPUT_DIRECTORY
# ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# wolfSSL JNI/JSSE library wil be compiled as SHARED library
# wolfSSL JNI Java files are tied into build in Module build.gradle file
add_library(wolfssljni SHARED
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSL.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLCertManager.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLCertRequest.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLCertificate.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLContext.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLSession.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLX509Name.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLX509StoreCtx.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfCryptECC.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfCryptEccKey.c
        ${wolfssljni_DIR}/native/com_wolfssl_WolfCryptRSA.c
)

# set_target_properties(wolfssljni PROPERTIES LIBRARY_OUTPUT_DIRECTORY
# ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})

# Find the android log library, store into variable ${lib-log}
find_library(lib-log log)

# Link libwolfssl to android log library
target_link_libraries(
        wolfssl
        ${lib-log}
)

# Link libwolfssljni to libwolfssl
target_link_libraries(
        wolfssljni
        wolfssl
)
