
# Definitions for building the wolfSSL JNI library and native code

LOCAL_PATH := $(call my-dir)

javac_flags:=-Xmaxwarns 9999999
native_cflags := -Wall

# Create the wolfSSL JNI library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(call all-java-files-under,src/java)
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVACFLAGS := $(javac_flags)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := wolfssljni
LOCAL_REQUIRED_MODULES := libwolfssljni libwolfssl
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_JAVA_LIBRARY)

# Create wolfSSL JNI native library
include $(CLEAR_VARS)
LOCAL_CFLAGS += $(native_cflags)
LOCAL_CFLAGS:= -DWOLFSSL_JNI -DWOLFSSL_DTLS -DOPENSSL_EXTRA -DHAVE_CRL -DHAVE_OCSP -DHAVE_CRL_MONITOR -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER -DHAVE_ECC -DTFM_ECC256 -DHAVE_PK_CALLBACKS -DHAVE_DH -DWOLFSSL_CERT_EXT -DWOLFSSL_CERT_GEN -DUSE_FAST_MATH -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DHAVE_TLS_EXTENSIONS -DHAVE_SNI -DHAVE_MAX_FRAGMENT -DHAVE_TRUNCATED_HMAC -DHAVE_ALPN -DHAVE_TRUSTED_CA -DHAVE_SUPPORTED_CURVES -Os -fomit-frame-pointer
LOCAL_SRC_FILES := \
    native/com_wolfssl_wolfcrypt_ECC.c \
    native/com_wolfssl_wolfcrypt_EccKey.c \
    native/com_wolfssl_wolfcrypt_RSA.c \
    native/com_wolfssl_WolfSSL.c \
    native/com_wolfssl_WolfSSLCertificate.c \
    native/com_wolfssl_WolfSSLCertManager.c \
    native/com_wolfssl_WolfSSLContext.c \
    native/com_wolfssl_WolfSSLSession.c
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

