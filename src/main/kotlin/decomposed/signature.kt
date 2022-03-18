package decomposed

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSequence

//=============================================================
//  signature AlgorithmIdentifier
/*
    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm OBJECT IDENTIFIER,
        parameters ANY DEFINED BY algorithm OPTIONAL  }
 */

val signatureAlgorithm: DERSequence = run {
    val signatureAlgorithmIdentifier_ASN: ASN1EncodableVector = ASN1EncodableVector()
    signatureAlgorithmIdentifier_ASN.add(ASN1ObjectIdentifier("1.2.840.113549.1.1.5"))
    signatureAlgorithmIdentifier_ASN.add(DERNull.INSTANCE)
    DERSequence(signatureAlgorithmIdentifier_ASN)
}
