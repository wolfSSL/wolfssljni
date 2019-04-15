
if [ -z "$1" ]; then
    echo "Expected provider location for bouncy castle."
    echo "Example \"./convert-to-bks.sh ~/Downloads/bcprov-jdk15on-161.jar\""
    exit 1
fi
PROVIDER="$1"

convert () {
keytool -importkeystore -srckeystore ${1}.jks -destkeystore ${1}.bks -srcstoretype JKS -deststoretype BKS -srcstorepass "wolfSSL test" -deststorepass "wolfSSL test" -provider org.bouncycastle.jce.provider.BouncyCastleProvider --providerpath "$PROVIDER"

}

rm -f server.bks &> /dev/null
convert "server"

rm -f client.bks &> /dev/null
convert "client"

rm -f rsa.bks &> /dev/null
convert "rsa"

rm -f all.bks &> /dev/null
convert "all"

rm -f all_mixed.bks &> /dev/null
convert "all_mixed"

rm -f cacerts.bks &> /dev/null
convert "cacerts"

rm -f ecc.bks &> /dev/null
convert "ecc"
