
if [ -z "$1" ]; then
    echo "Expected provider location for bouncy castle."
    echo "Example \"./convert-to-bks.sh ~/Downloads/bcprov-jdk15on-161.jar\""
    exit 1
fi
PROVIDER="$1"

convert () {
keytool -importkeystore -srckeystore ${1}.jks -destkeystore ${1}.bks -srcstoretype JKS -deststoretype BKS -srcstorepass "wolfSSL test" -deststorepass "wolfSSL test" -provider org.bouncycastle.jce.provider.BouncyCastleProvider --providerpath "$PROVIDER"

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

