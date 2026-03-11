#!/bin/bash

# DualProviderFIPSTest.sh
#
# Script to run the DualProviderFIPSTest example. Tests using both
# WolfCryptProvider (wolfJCE) and WolfSSLProvider (wolfJSSE) together with
# wolfCrypt FIPS / FIPS Ready.
#
# Requires:
#   - wolfSSL built with --enable-fips=ready --enable-jni (or FIPS)
#   - wolfcrypt-jni (wolfJCE) built and JARs available
#   - wolfssljni (wolfJSSE) built and JARs available
#   - Both native JNI libraries on LD_LIBRARY_PATH
#
# Environment variables:
#   WOLFCRYPTJNI_DIR - path to wolfcrypt-jni build directory
#                      (default: ../../wolfcryptjni)

WOLFCRYPTJNI_DIR="${WOLFCRYPTJNI_DIR:-../../wolfcryptjni}"

java -classpath \
    lib/wolfssl.jar:lib/wolfssl-jsse.jar:"${WOLFCRYPTJNI_DIR}"/lib/wolfcrypt-jni.jar:examples/provider \
    DualProviderFIPSTest
