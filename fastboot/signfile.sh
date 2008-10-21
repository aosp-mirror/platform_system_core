#!/bin/bash

if [ $# -ne 3 ]
then
 echo "Usage: $0 alias filename passpharse"
 exit -1
fi

openssl dgst -passin pass:"$3" -binary -sha1 -sign $1.pem $2 > $2.sign

