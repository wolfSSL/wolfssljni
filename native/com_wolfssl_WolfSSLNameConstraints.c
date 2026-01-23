/* com_wolfssl_WolfSSLNameConstraints.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/openssl/x509v3.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLNameConstraints.h"

/* Maximum reasonable string length to prevent excessive allocation (64KB) */
#define NC_MAX_STRING_LEN 65536

/* Name Constraints API was added after wolfSSL 5.8.4 in PR 9705. Version
 * check must be greater than 5.8.4 or patch from PR 9705 must be applied
 * and WOLFSSL_PR9705_PATCH_APPLIED defined when compiling this JNI wrapper. */

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1NAME_1CONSTRAINTS_1free
  (JNIEnv* jenv, jclass jcl, jlong ncPtr)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    (void)jenv;
    (void)jcl;

    if (ncPtr != 0) {
        wolfSSL_NAME_CONSTRAINTS_free(
            (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr);
    }
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1NAME_1CONSTRAINTS_1permittedNum
  (JNIEnv* jenv, jclass jcl, jlong ncPtr)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    WOLFSSL_NAME_CONSTRAINTS* nc =
        (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr;
    (void)jenv;
    (void)jcl;

    if (nc == NULL || nc->permittedSubtrees == NULL) {
        return 0;
    }
    return (jint)wolfSSL_sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1NAME_1CONSTRAINTS_1excludedNum
  (JNIEnv* jenv, jclass jcl, jlong ncPtr)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    WOLFSSL_NAME_CONSTRAINTS* nc =
        (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr;
    (void)jenv;
    (void)jcl;

    if (nc == NULL || nc->excludedSubtrees == NULL) {
        return 0;
    }
    return (jint)wolfSSL_sk_GENERAL_SUBTREE_num(nc->excludedSubtrees);
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1GENERAL_1SUBTREE_1getBaseType
  (JNIEnv* jenv, jclass jcl, jlong ncPtr, jboolean permitted, jint idx)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    WOLFSSL_NAME_CONSTRAINTS* nc =
        (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr;
    WOLFSSL_STACK* sk;
    WOLFSSL_GENERAL_SUBTREE* subtree;
    int skNum;
    (void)jenv;
    (void)jcl;

    if (nc == NULL) {
        return -1;
    }

    sk = permitted ? nc->permittedSubtrees : nc->excludedSubtrees;
    if (sk == NULL) {
        return -1;
    }

    /* Bounds check for idx to prevent out-of-bounds access */
    skNum = wolfSSL_sk_GENERAL_SUBTREE_num(sk);
    if (idx < 0 || idx >= skNum) {
        return -1;
    }

    subtree = wolfSSL_sk_GENERAL_SUBTREE_value(sk, (int)idx);
    if (subtree == NULL || subtree->base == NULL) {
        return -1;
    }

    return (jint)subtree->base->type;
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
    (void)permitted;
    (void)idx;
    return -1;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1GENERAL_1SUBTREE_1getBaseValue
  (JNIEnv* jenv, jclass jcl, jlong ncPtr, jboolean permitted, jint idx)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    WOLFSSL_NAME_CONSTRAINTS* nc =
        (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr;
    WOLFSSL_STACK* sk;
    WOLFSSL_GENERAL_SUBTREE* subtree;
    WOLFSSL_GENERAL_NAME* gn;
    const unsigned char* str = NULL;
    int strLen = 0;
    int skNum;
    char* buf = NULL;
    jstring result = NULL;
    (void)jcl;

    if (nc == NULL || jenv == NULL) {
        return NULL;
    }

    sk = permitted ? nc->permittedSubtrees : nc->excludedSubtrees;
    if (sk == NULL) {
        return NULL;
    }

    /* Bounds check for idx to prevent out-of-bounds access */
    skNum = wolfSSL_sk_GENERAL_SUBTREE_num(sk);
    if (idx < 0 || idx >= skNum) {
        return NULL;
    }

    subtree = wolfSSL_sk_GENERAL_SUBTREE_value(sk, (int)idx);
    if (subtree == NULL || subtree->base == NULL) {
        return NULL;
    }

    gn = subtree->base;

    switch (gn->type) {
        case WOLFSSL_GEN_DNS:
        case WOLFSSL_GEN_EMAIL:
        case WOLFSSL_GEN_URI:
            if (gn->d.ia5 != NULL) {
                str = wolfSSL_ASN1_STRING_get0_data(gn->d.ia5);
                strLen = wolfSSL_ASN1_STRING_length(gn->d.ia5);
            }
            break;

        case WOLFSSL_GEN_DIRNAME:
            if (gn->d.directoryName != NULL) {
                /* Convert X509_NAME to one-line string */
                buf = wolfSSL_X509_NAME_oneline(gn->d.directoryName, NULL, 0);
                if (buf != NULL) {
                    result = (*jenv)->NewStringUTF(jenv, buf);
                    XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);
                    return result;
                }
            }
            return NULL;

        case WOLFSSL_GEN_IPADD:
            /* For IP addresses, return address/mask notation.
             * IPv4 (8 bytes): "192.168.1.0/255.255.255.0"
             * IPv6 (32 bytes): "fe80:0000:...:0001/ffff:ffff:...:0000" */
            if (gn->d.ip != NULL) {
                int i;
                int ipLen = wolfSSL_ASN1_STRING_length(gn->d.ip);
                const unsigned char* ipData =
                    wolfSSL_ASN1_STRING_get0_data(gn->d.ip);

                if (ipData != NULL && ipLen > 0 && ipLen <= 32) {
                    if (ipLen == 8) {
                        /* IPv4: 4 bytes IP + 4 bytes mask */
                        /* Max: "255.255.255.255/255.255.255.255" = 31 chars */
                        buf = (char*)XMALLOC(40, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        if (buf != NULL) {
                            XSNPRINTF(buf, 40, "%d.%d.%d.%d/%d.%d.%d.%d",
                                ipData[0], ipData[1], ipData[2], ipData[3],
                                ipData[4], ipData[5], ipData[6], ipData[7]);
                            result = (*jenv)->NewStringUTF(jenv, buf);
                            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            return result;
                        }
                    }
                    else if (ipLen == 32) {
                        /* IPv6: 16 bytes IP + 16 bytes mask
                         * Format: "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/
                         *          yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy"
                         * 8 groups * 4 chars + 7 colons = 39 chars per addr
                         * 39 + 1 (slash) + 39 = 79 chars + null = 80 */
                        buf = (char*)XMALLOC(80, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        if (buf != NULL) {
                            int pos = 0;
                            /* Format address (first 16 bytes) */
                            for (i = 0; i < 16; i += 2) {
                                if (i > 0) {
                                    buf[pos++] = ':';
                                }
                                XSNPRINTF(buf + pos, 5, "%02x%02x",
                                    ipData[i], ipData[i + 1]);
                                pos += 4;
                            }
                            buf[pos++] = '/';
                            /* Format mask (next 16 bytes) */
                            for (i = 16; i < 32; i += 2) {
                                if (i > 16) {
                                    buf[pos++] = ':';
                                }
                                XSNPRINTF(buf + pos, 5, "%02x%02x",
                                    ipData[i], ipData[i + 1]);
                                pos += 4;
                            }
                            buf[pos] = '\0';
                            result = (*jenv)->NewStringUTF(jenv, buf);
                            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            return result;
                        }
                    }
                    else {
                        /* Other lengths: return colon-separated hex bytes */
                        int bufLen = ipLen * 3;
                        buf = (char*)XMALLOC(bufLen, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
                        if (buf != NULL) {
                            int pos = 0;
                            for (i = 0; i < ipLen; i++) {
                                if (i > 0) {
                                    buf[pos++] = ':';
                                }
                                XSNPRINTF(buf + pos, 3, "%02X", ipData[i]);
                                pos += 2;
                            }
                            buf[pos] = '\0';
                            result = (*jenv)->NewStringUTF(jenv, buf);
                            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                            return result;
                        }
                    }
                }
            }
            return NULL;

        default:
            return NULL;
    }

    /* Validate strLen to prevent excessive allocation */
    if (str != NULL && strLen > 0 && strLen <= NC_MAX_STRING_LEN) {
        /* Create null-terminated copy for JNI NewStringUTF */
        buf = (char*)XMALLOC(strLen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf != NULL) {
            XMEMCPY(buf, str, strLen);
            buf[strLen] = '\0';
            result = (*jenv)->NewStringUTF(jenv, buf);
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    return result;
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
    (void)permitted;
    (void)idx;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLNameConstraints_wolfSSL_1NAME_1CONSTRAINTS_1check_1name
  (JNIEnv* jenv, jclass jcl, jlong ncPtr, jint type, jstring name)
{
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS) && \
    ((LIBWOLFSSL_VERSION_HEX > 0x05008004) || \
     defined(WOLFSSL_PR9705_PATCH_APPLIED))
    WOLFSSL_NAME_CONSTRAINTS* nc =
        (WOLFSSL_NAME_CONSTRAINTS*)(uintptr_t)ncPtr;
    const char* nameStr = NULL;
    int nameLen = 0;
    int ret = 0;
    (void)jcl;

    if (nc == NULL || jenv == NULL || name == NULL) {
        return 0;
    }

    /* Get the name string from Java */
    nameStr = (*jenv)->GetStringUTFChars(jenv, name, NULL);
    if (nameStr == NULL) {
        return 0;
    }
    nameLen = (int)(*jenv)->GetStringUTFLength(jenv, name);

    /* Call native wolfSSL function */
    ret = wolfSSL_NAME_CONSTRAINTS_check_name(nc, (int)type, nameStr, nameLen);

    /* Release the string */
    (*jenv)->ReleaseStringUTFChars(jenv, name, nameStr);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)ncPtr;
    (void)type;
    (void)name;
    return 0;
#endif
}

