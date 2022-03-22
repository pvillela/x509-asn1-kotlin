# Converet generated certificate from PEM to text format
openssl x509 -inform der -in bin/cert-decomposed.der -text -out bin/cert-decomposed.txt
