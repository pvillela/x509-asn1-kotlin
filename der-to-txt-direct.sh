# Converet generated certificate from PEM to text format
openssl x509 -inform der -in bin/cert-direct.der -text -out bin/cert-direct.txt
