#!/bin/bash

# Simple script to run Facebook Infer over java files included in this package.
#
# This is set up to run entire infer over Java classes in this package. To
# only run the RacerD thread safety analysis tool, change the command
# invocation below from "run" to "--racerd-only", ie:
#
# infer --racerd-only -- javac \
#
# Run from wolfssljni root:
#
#    $ cd wolfssljni
#    $ ./scripts/infer.sh
#
# By default the generated output and logs from Infer will be deleted. To keep
# them, pass 'keep' to the script:
#
#    $ ./scripts/infer.sh keep
#
# wolfSSL Inc, April 2024
#
#

# These variables may be overridden on the command line.
KEEP="${KEEP:-no}"

while [ "$1" ]; do
  if [ "$1" = 'keep' ]; then
      KEEP='yes';
  fi
  shift
done

infer --fail-on-issue run -- javac \
    src/java/com/wolfssl/WolfSSL.java \
    src/java/com/wolfssl/WolfSSLALPNSelectCallback.java \
    src/java/com/wolfssl/WolfSSLByteBufferIORecvCallback.java \
    src/java/com/wolfssl/WolfSSLByteBufferIOSendCallback.java \
    src/java/com/wolfssl/WolfSSLCertManager.java \
    src/java/com/wolfssl/WolfSSLCertRequest.java \
    src/java/com/wolfssl/WolfSSLCertificate.java \
    src/java/com/wolfssl/WolfSSLContext.java \
    src/java/com/wolfssl/WolfSSLDebug.java \
    src/java/com/wolfssl/WolfSSLDecryptVerifyCallback.java \
    src/java/com/wolfssl/WolfSSLEccSharedSecretCallback.java \
    src/java/com/wolfssl/WolfSSLEccSignCallback.java \
    src/java/com/wolfssl/WolfSSLEccVerifyCallback.java \
    src/java/com/wolfssl/WolfSSLException.java \
    src/java/com/wolfssl/WolfSSLFIPSErrorCallback.java \
    src/java/com/wolfssl/WolfSSLGenCookieCallback.java \
    src/java/com/wolfssl/WolfSSLIORecvCallback.java \
    src/java/com/wolfssl/WolfSSLIOSendCallback.java \
    src/java/com/wolfssl/WolfSSLJNIException.java \
    src/java/com/wolfssl/WolfSSLLoggingCallback.java \
    src/java/com/wolfssl/WolfSSLMacEncryptCallback.java \
    src/java/com/wolfssl/WolfSSLMissingCRLCallback.java \
    src/java/com/wolfssl/WolfSSLNativeLoggingCallback.java \
    src/java/com/wolfssl/WolfSSLPskClientCallback.java \
    src/java/com/wolfssl/WolfSSLPskServerCallback.java \
    src/java/com/wolfssl/WolfSSLRsaDecCallback.java \
    src/java/com/wolfssl/WolfSSLRsaEncCallback.java \
    src/java/com/wolfssl/WolfSSLRsaSignCallback.java \
    src/java/com/wolfssl/WolfSSLRsaVerifyCallback.java \
    src/java/com/wolfssl/WolfSSLSession.java \
    src/java/com/wolfssl/WolfSSLSessionTicketCallback.java \
    src/java/com/wolfssl/WolfSSLTls13SecretCallback.java \
    src/java/com/wolfssl/WolfSSLVerifyCallback.java \
    src/java/com/wolfssl/WolfSSLVerifyDecryptCallback.java \
    src/java/com/wolfssl/WolfSSLX509Name.java \
    src/java/com/wolfssl/WolfSSLX509StoreCtx.java \
    src/java/com/wolfssl/WolfCryptECC.java \
    src/java/com/wolfssl/WolfCryptEccKey.java \
    src/java/com/wolfssl/WolfCryptRSA.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLAuthStore.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLContext.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLCustomUser.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLEngine.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLEngineHelper.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLGenericHostName.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLImplementSSLSession.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLInternalVerifyCb.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLKeyManager.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLKeyX509.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLParametersHelper.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLParameters.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLProvider.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLSNIServerName.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLServerSocket.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLServerSocketFactory.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLSessionContext.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLSocketFactory.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLSocket.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLTrustManager.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLTrustX509.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLUtil.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLX509.java \
    src/java/com/wolfssl/provider/jsse/WolfSSLX509X.java \
    src/java/com/wolfssl/provider/jsse/adapter/WolfSSLJDK8Helper.java

RETVAL=$?

# remove compiled class files
rm -r ./com

# remove infer out directory (comment this out to inspect logs if needed)
if [ "$RETVAL" == '0' ] && [ "$KEEP" == 'no' ]; then
    rm -r ./infer-out
fi

if [ "$RETVAL" == '1' ] || [ "$RETVAL" == '2' ]; then
    # GitHub Actions expects return of 1 to mark step as failure
    exit 1
fi

exit 0

