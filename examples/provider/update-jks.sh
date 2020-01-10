
# Used to update all of the JKS stores
printf "Removing and updating JKS stores\n"
if [ -z "$1" ]; then
    printf "\tNo directory to certs provided\n"
    printf "\tExample use ./update-jks.sh ~/wolfssl/certs\n"
    exit 1;
fi
CERT_LOCATION=$1

# keystore-name , cert file , alias , password
add_cert() {
    keytool -import -keystore "$1" -file "$CERT_LOCATION/$2" -alias "$3" -noprompt -trustcacerts -storepass "$4"
    if [ $? -ne 0 ]; then
        printf "fail"
        exit 1
    fi
}

# keystore-name , cert file , key file , alias , password
add_cert_key() {
    openssl pkcs12 -export -in "$CERT_LOCATION/$2" -inkey "$CERT_LOCATION/$3" -out tmp.p12 -passin pass:"$5" -passout pass:"$5" -name "$4" &> /dev/null
    keytool -importkeystore -deststorepass "$5" -destkeystore "$1" -srckeystore tmp.p12 -srcstoretype PKCS12 -srcstorepass "$5" -alias "$4" &> /dev/null
    if [ $? -ne 0 ]; then
        printf "fail"
        exit 1
    fi
    rm tmp.p12
}
printf "\tCreating all.jks ..."
rm all.jks &> /dev/null
add_cert_key "all.jks" "/client-cert.pem" "/client-key.pem" "client" "wolfSSL test"
add_cert_key "all.jks" "/1024/client-cert.pem" "/1024/client-key.pem" "client-1024" "wolfSSL test"
add_cert_key "all.jks" "/server-cert.pem" "/server-key.pem" "server" "wolfSSL test"
add_cert_key "all.jks" "/1024/server-cert.pem" "/1024/server-key.pem" "server-1024" "wolfSSL test"
add_cert_key "all.jks" "/client-ecc-cert.pem" "/ecc-client-key.pem" "client-ecc" "wolfSSL test"
add_cert_key "all.jks" "/server-ecc.pem" "/ecc-key.pem" "server-ecc" "wolfSSL test"
add_cert_key "all.jks" "/ca-cert.pem" "/ca-key.pem" "ca" "wolfSSL test"
add_cert_key "all.jks" "/1024/ca-cert.pem" "/1024/ca-key.pem" "ca-1024" "wolfSSL test"
add_cert_key "all.jks" "/ca-ecc-cert.pem" "/ca-ecc-key.pem" "ca-ecc" "wolfSSL test"
printf "done\n"

printf "\tCreating client.jks ..."
rm client.jks &> /dev/null
add_cert_key "client.jks" "/client-cert.pem" "/client-key.pem" "client" "wolfSSL test"
add_cert_key "client.jks" "/1024/client-cert.pem" "/1024/client-key.pem" "client-1024" "wolfSSL test"
add_cert_key "client.jks" "/client-ecc-cert.pem" "/ecc-client-key.pem" "client-ecc" "wolfSSL test"
add_cert_key "client.jks" "/ca-ecc-cert.pem" "/ca-ecc-key.pem" "ca-ecc" "wolfSSL test"
add_cert_key "client.jks" "/ca-cert.pem" "/ca-key.pem" "ca" "wolfSSL test"
add_cert_key "client.jks" "/1024/ca-cert.pem" "/1024/ca-key.pem" "ca-1024" "wolfSSL test"
printf "done\n"

printf "\tCreating server.jks ..."
rm server.jks &> /dev/null
add_cert_key "server.jks" "/server-cert.pem" "/server-key.pem" "server" "wolfSSL test"
add_cert_key "server.jks" "/1024/server-cert.pem" "/1024/server-key.pem" "server-1024" "wolfSSL test"
add_cert_key "server.jks" "/server-ecc.pem" "/ecc-key.pem" "server-ecc" "wolfSSL test"
add_cert_key "server.jks" "/client-ecc-cert.pem" "/ecc-client-key.pem" "client-ecc" "wolfSSL test"
add_cert_key "server.jks" "/client-cert.pem" "/client-key.pem" "client" "wolfSSL test"
add_cert_key "server.jks" "/1024/client-cert.pem" "/1024/client-key.pem" "client-1024" "wolfSSL test"
printf "done\n"

printf "\tCreating rsa.jks ..."
rm rsa.jks &> /dev/null
add_cert_key "rsa.jks" "/client-cert.pem" "/client-key.pem" "client" "wolfSSL test"
add_cert_key "rsa.jks" "/server-cert.pem" "/server-key.pem" "server" "wolfSSL test"
add_cert_key "rsa.jks" "/ca-cert.pem" "/ca-key.pem" "ca" "wolfSSL test"
printf "done\n"

printf "\tCreating ecc.jks ..."
rm ecc.jks &> /dev/null
add_cert_key "ecc.jks" "/client-ecc-cert.pem" "/ecc-client-key.pem" "client-ecc" "wolfSSL test"
add_cert_key "ecc.jks" "/server-ecc.pem" "/ecc-key.pem" "server-ecc" "wolfSSL test"
printf "done\n"

printf "\tCreating all_mixed.jks ..."
rm all_mixed.jks &> /dev/null
add_cert_key "all_mixed.jks" "/client-ecc-cert.pem" "/ecc-client-key.pem" "client-ecc" "wolfSSL test"
add_cert_key "all_mixed.jks" "/ca-cert.pem" "/ca-key.pem" "ca" "wolfSSL test"
add_cert_key "all_mixed.jks" "/1024/client-cert.pem" "/1024/client-key.pem" "client-1024" "wolfSSL test"
add_cert_key "all_mixed.jks" "/client-cert.pem" "/client-key.pem" "client" "wolfSSL test"
add_cert_key "all_mixed.jks" "/server-ecc.pem" "/ecc-key.pem" "server-ecc" "wolfSSL test"
add_cert_key "all_mixed.jks" "/server-cert.pem" "/server-key.pem" "server" "wolfSSL test"
add_cert_key "all_mixed.jks" "/1024/server-cert.pem" "/1024/server-key.pem" "server-1024" "wolfSSL test"
add_cert_key "all_mixed.jks" "/1024/ca-cert.pem" "/1024/ca-key.pem" "ca-1024" "wolfSSL test"
printf "done\n"

