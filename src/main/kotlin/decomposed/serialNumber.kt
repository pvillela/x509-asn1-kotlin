package decomposed

import org.bouncycastle.asn1.ASN1Integer
import java.math.BigInteger

//=============================================================
//  serialNumber CertificateSerialNumber
/*
    CertificateSerialNumber  ::=  INTEGER
 */

val serialNumber: ASN1Integer = run {
    // Create 9-byte serial number consistent with RFC5280
    val bytes = ByteArray(9)
    random.nextBytes(bytes)
    val bigInteger = BigInteger(1, bytes)
    ASN1Integer(bigInteger)
}
