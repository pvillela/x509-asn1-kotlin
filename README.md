# x509-asn1-kotlin

Kotlin implementation of an X.509 certificate using the [Bouncy Castle](https://github.com/bcgit/bc-java) library's ASN.1 capabilities.

Based on [Constructing an X.509 Certificate Using ASN.1](https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/).

[src/main/kotlin/cert/certFroomAsn1_direct](https://github.com/pvillela/x509-asn1-kotlin/blob/main/src/main/kotlin/cert/certFromAsn1_direct.kt) is a mostly direct translation of the article's original code to Kotlin, except for the improvement of using the cryptographically-secure pseudorandom number generator `java.Security.SecureRandom` instead of `Math.random`.

[src/main/kotlin/cert/certFroomAsn1_improved](https://github.com/pvillela/x509-asn1-kotlin/blob/main/src/main/kotlin/cert/certFromAsn1_improved.kt) adds block comments with relevant fragments of the ASN.1 specification of X.509 certs from [RFC5912](https://datatracker.ietf.org/doc/html/rfc5912), adds further clarifying comments, and renames some variables.

[src/main/kotlin/cert/decomposed](https://github.com/pvillela/x509-asn1-kotlin/tree/main/src/main/kotlin/cert/decomposed) contains the decomposition of [src/main/kotlin/cert/certFroomAsn1_improved](https://github.com/pvillela/x509-asn1-kotlin/blob/main/src/main/kotlin/cert/certFromAsn1_improved.kt) into a set of separate files, one for each element of the certificate. The [main.kt](https://github.com/pvillela/x509-asn1-kotlin/blob/main/src/main/kotlin/cert/decomposed/main.kt) file contains the main function that produces the cert.

For each of the above code versions, the main function produces a cert in binary DER format in a `bin` directory at the same level as the `src` directory.

The shell scripts [der-to-txt-direct.sh](https://github.com/pvillela/x509-asn1-kotlin/blob/main/der-to-txt-direct.sh), [der-to-txt-improved.sh](https://github.com/pvillela/x509-asn1-kotlin/blob/main/der-to-txt-improved.sh), [der-to-txt-decomposed.sh](https://github.com/pvillela/x509-asn1-kotlin/blob/main/der-to-txt-decomposed.sh) convert each of the DER files to a corresonding text file using OpenSSL.
