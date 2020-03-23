
# Definitions for building the wolfSSL JNI library and native code

LOCAL_PATH := $(call my-dir)

javac_flags:=-Xmaxwarns 9999999
native_cflags := -Wall

# Create the wolfSSL JNI library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(call all-java-files-under,src/java)
LOCAL_JAVACFLAGS := $(javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := wolfssljni
LOCAL_REQUIRED_MODULES := libwolfssljni libwolfssl
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_JAVA_LIBRARIES := core-libart
include $(BUILD_JAVA_LIBRARY)

# Create wolfSSL JNI native library
include $(CLEAR_VARS)
LOCAL_CFLAGS += $(native_cflags)
LOCAL_CFLAGS:= -DHAVE_FFDHE_2048 -DWOLFSSL_TLS13 -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_AESGCM -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_HKDF -DNO_DSA -DHAVE_ECC -DTFM_ECC256 -DECC_SHAMIR -DWC_RSA_PSS -DWOLFSSL_BASE64_ENCODE -DNO_RC4 -DNO_HC128 -DNO_RABBIT -DWOLFSSL_SHA224 -DWOLFSSL_SHA3 -DHAVE_POLY1305 -DHAVE_ONE_TIME_AUTH -DHAVE_CHACHA -DHAVE_HASHDRBG -DHAVE_TLS_EXTENSIONS -DHAVE_SUPPORTED_CURVES -DHAVE_EXTENDED_MASTER -DWOLFSSL_JNI -DWOLFSSL_DTLS -DOPENSSL_EXTRA -DHAVE_CRL -DHAVE_OCSP -DHAVE_CRL_MONITOR -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER -DHAVE_PK_CALLBACKS -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN -DHAVE_ENCRYPT_THEN_MAC -DNO_MD4 -DWOLFSSL_ENCRYPTED_KEYS -DUSE_FAST_MATH -DNO_DES3 -DKEEP_PEER_CERT -Os -fomit-frame-pointer
LOCAL_SRC_FILES := \
    native/com_wolfssl_wolfcrypt_ECC.c \
    native/com_wolfssl_wolfcrypt_EccKey.c \
    native/com_wolfssl_wolfcrypt_RSA.c \
    native/com_wolfssl_WolfSSL.c \
    native/com_wolfssl_WolfSSLCertificate.c \
    native/com_wolfssl_WolfSSLCertManager.c \
    native/com_wolfssl_WolfSSLContext.c \
    native/com_wolfssl_WolfSSLSession.c \
    native/com_wolfssl_WolfSSLX509StoreCtx.c
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/native \
    external/wolfssl
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/native
LOCAL_SHARED_LIBRARIES := libwolfssl
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := libwolfssljni
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_SHARED_LIBRARY)

# Clear local variables
native_cflags :=
javac_flags :=

