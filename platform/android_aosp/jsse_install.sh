#!/bin/bash

# wolfSSL and wolfSSL JNI AOSP Install Script
#
# This script will install necessary source files from the wolfSSL C library
# source directory and the wolfSSL JNI source directory into an Android
# OSP (Open Source Project) working source tree.
#
# This script is used as one step to install wolfJSSE as an alternate SSL/TLS
# Security Provider into Android AOSP.
#
# Before using this script, please read:
#
#     1) README.android_asop (located in this same directory)
#     2) "Installing a JSSE Provider in Android AOSP" document, by wolfSSL
#
# Copyright (C) 2020, wolfSSL Inc.

if [ "$#" -lt 3 ]; then
    echo "-------------------------------------------" >&2
    echo "wolfSSL and wolfSSL JNI AOSP Install Script" >&2
    echo "-------------------------------------------" >&2
    echo "Usage: $0 [wolfssl_dir] [wolfssljni_dir] [aosp_dir]" >&2
    echo "    [wolfssl_dir]: wolfSSL library source directory" >&2
    echo "    [wolfssljni_dir]: wolfssljni source directory" >&2
    echo "    [aosp_dir]: Android AOSP working source directory" >&2
    echo "" >&2
    echo "Note: This script will copy files into AOSP directory" >&2
    echo "" >&2
    exit 1
fi

wolfssl_dir=$1
wolfssljni_dir=$2
aosp_dir=$3

# Check if directories exist
if [ ! -d $wolfssl_dir ]; then
    echo "wolfSSL directory does not exist: $wolfssl_dir"
    exit 1
fi

if [ ! -d $wolfssljni_dir ]; then
    echo "wolfSSL JNI directory does not exist: $wolfssljni_dir"
    exit 1
fi

if [ ! -d $aosp_dir ]; then
    echo "Android AOSP directory does not exist: $aosp_dir"
    exit 1
fi

if [ ! -d $wolfssljni_dir/platform/android_aosp ]; then
    echo "wolfSSL JNI does not contain 'platform/android_aosp' directory"
    exit 1
fi

# Check if AOSP files exist in wolfssljni bundle
jni_has_aosp=1
jni_aosp=$wolfssljni_dir/platform/android_aosp

if [ ! -f $jni_aosp/wolfssl/Android.mk ]; then
    jni_has_aosp=0
fi

if [ ! -f $jni_aosp/wolfssl/CleanSpec.mk ]; then
    jni_has_aosp=0
fi

if [ ! -f $jni_aosp/wolfssljni/Android.mk ]; then
    jni_has_aosp=0
fi

if [ $jni_has_aosp -eq 0 ]; then
    echo "wolfSSL JNI does not contain necessary AOSP files, check bundle"
    exit 1
fi

aosp_wolfssl=$aosp_dir/external/wolfssl
aosp_wolfssljni=$aosp_dir/external/wolfssljni

# Copy wolfSSL sources over to AOSP code tree
if [ -d $aosp_wolfssl ]; then
    echo "$aosp_wolfssl already exists, skipping wolfSSL copy"
else
    mkdir -p $aosp_wolfssl
    cp $jni_aosp/wolfssl/Android.mk $aosp_wolfssl
    cp $jni_aosp/wolfssl/CleanSpec.mk $aosp_wolfssl

    cp -r $wolfssl_dir/certs $aosp_wolfssl/certs
    cp -r $wolfssl_dir/src $aosp_wolfssl/src
    cp -r $wolfssl_dir/wolfcrypt $aosp_wolfssl/wolfcrypt
    cp -r $wolfssl_dir/wolfssl $aosp_wolfssl/wolfssl

    cp $wolfssl_dir/README $aosp_wolfssl
    cp $wolfssl_dir/COPYING $aosp_wolfssl
fi

# Copy wolfSSL JNI sources over to AOSP code tree
if [ -d $aosp_wolfssljni ]; then
    echo "$aosp_wolfssljni already exists, skipping wolfSSL copy"
else
    mkdir -p $aosp_wolfssljni
    cp $jni_aosp/wolfssljni/Android.mk $aosp_wolfssljni

    cp -r $wolfssljni_dir/* $aosp_wolfssljni
fi

echo "All Files copied into Android AOSP source tree."
echo ""

