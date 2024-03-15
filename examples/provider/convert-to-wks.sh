
if [ -z "$1" ]; then
    echo "Expected provider location for wolfJCE provider JAR directory."
    echo "Example \"./convert-to-wks.sh ~/wolfcryptjni/lib\""
    exit 1
fi
PROVIDER_DIR="$1"

# Export library paths for Linux and Mac to find shared JNI library
export LD_LIBRARY_PATH=$PROVIDER_DIR:$LD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=$PROVIDER_DIR:$DYLD_LIBRARY_PATH

convert () {
keytool -importkeystore -srckeystore ${1}.jks -destkeystore ${1}.wks -srcstoretype JKS -deststoretype WKS -srcstorepass "wolfSSL test" -deststorepass "wolfSSL test" -provider com.wolfssl.provider.jce.WolfCryptProvider --providerpath "$PROVIDER_DIR/wolfcrypt-jni.jar"

}

rm -f all.bks &> /dev/null
convert "all"

rm -f all_mixed.bks &> /dev/null
convert "all_mixed"

rm -f client.bks &> /dev/null
convert "client"

rm -f client-rsa-1024.bks &> /dev/null
convert "client-rsa-1024"

rm -f client-rsa.bks &> /dev/null
convert "client-rsa"

rm -f client-ecc.bks &> /dev/null
convert "client-ecc"

rm -f server.bks &> /dev/null
convert "server"

rm -f server-rsa-1024.bks &> /dev/null
convert "server-rsa-1024"

rm -f server-rsa.bks &> /dev/null
convert "server-rsa"

rm -f server-ecc.bks &> /dev/null
convert "server-ecc"

rm -f cacerts.bks &> /dev/null
convert "cacerts"

rm -f ca-client.bks &> /dev/null
convert "ca-client"

rm -f ca-server.bks &> /dev/null
convert "ca-server"

