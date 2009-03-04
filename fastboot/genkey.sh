#!/bin/bash

if [ $# -ne 2 ]
then
 echo "Usage: $0 alias \"pass phrase\""
 exit -1
fi

# Generate a 2048 bit RSA key with public exponent 3.
# Encrypt private key with provided password.
openssl genrsa -3 -out $1.pem -passout pass:"$2" 2048

# Create a self-signed cert for this key.
openssl req -new -x509 -key $1.pem -passin pass:"$2" \
        -out $1-cert.pem \
        -batch -days 10000

# Create a PKCS12 store containing the generated private key.
# Protect the keystore and the private key with the provided password.
openssl pkcs12 -export -in $1-cert.pem -inkey $1.pem -passin pass:"$2" \
        -out $1.p12 -name $1 -passout pass:"$2"

rm $1.pem
rm $1-cert.pem

