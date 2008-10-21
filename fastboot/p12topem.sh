#!/bin/bash

if [ $# -ne 2 ]
then
 echo "Usage: $0 alias passphrase"
 exit -1
fi

openssl pkcs12 -passin pass:"$2" -passout pass:"$2" -in $1.p12 -out $1.pem
