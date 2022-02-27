# Converet generated certificate from PEM to text format
openssl x509 -inform der -in bin/cert-original.der -text -out bin/cert-original.txt
