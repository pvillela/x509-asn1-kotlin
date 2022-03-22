# Converet generated certificate from PEM to text format
openssl x509 -inform der -in bin/cert-improved.der -text -out bin/cert-improved.txt
