package decomposed

import org.bouncycastle.asn1.*
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest

//-------------------------------------------------------------
//  Subject Key Identifier
//  Authority Key Identifier
/*
    -- authority key identifier OID and syntax

    ext-AuthorityKeyIdentifier EXTENSION ::= { SYNTAX
        AuthorityKeyIdentifier IDENTIFIED BY
        id-ce-authorityKeyIdentifier }
    id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

    AuthorityKeyIdentifier ::= SEQUENCE {
        keyIdentifier             [0] KeyIdentifier            OPTIONAL,
        authorityCertIssuer       [1] GeneralNames             OPTIONAL,
        authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
        (WITH COMPONENTS {
        ...,
        authorityCertIssuer        PRESENT,
        authorityCertSerialNumber  PRESENT
        } |
        WITH COMPONENTS {
        ...,
        authorityCertIssuer        ABSENT,
        authorityCertSerialNumber  ABSENT
        })

    KeyIdentifier ::= OCTET STRING

    -- subject key identifier OID and syntax

    ext-SubjectKeyIdentifier EXTENSION ::= { SYNTAX
        KeyIdentifier IDENTIFIED BY id-ce-subjectKeyIdentifier }
    id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }

    -- PV: see GeneralNames in section `Subject Alternative Name` below
 */

//Calculate the keyIdentifier
// Same core key identifier for both issuer and subject because this is a self-signed cert
val keyIdentifier: DEROctetString = run {
    //Get the subjectPublicKey from SubjectPublicKeyInfo to calculate the keyIdentifier
    val subjectPublicKey = subjectPublicKeyInfo.getObjectAt(1).toASN1Primitive() as DERBitString

    val pubKeyBitStringBytes: ByteArray = subjectPublicKey.bytes
    val sha1: Digest = SHA1Digest()
    val pubKeydigestBytes = ByteArray(sha1.getDigestSize())
    sha1.update(pubKeyBitStringBytes, 0, pubKeyBitStringBytes.size)
    sha1.doFinal(pubKeydigestBytes, 0)
    DEROctetString(pubKeydigestBytes)
}

val subjectKeyIdentifier: DERSequence = run {
    //Subject Key Identifier
    val subjectKeyIdentifier_ASN = ASN1EncodableVector()
    subjectKeyIdentifier_ASN.add(ASN1ObjectIdentifier("2.5.29.14"))
    // Below additional wrapping with OCTET STRING is needed because of the definition
    // of the extnValue field in the above Extension SEQUENCE type.
    subjectKeyIdentifier_ASN.add(DEROctetString(keyIdentifier))
    DERSequence(subjectKeyIdentifier_ASN)
}

val authorityKeyIdentifier: DERSequence = run {
    //Authority Key Identifier
    val aki = DERTaggedObject(false, 0, keyIdentifier)
    val akiVec = ASN1EncodableVector()
    akiVec.add(aki)
    val akiSeq = DERSequence(akiVec)
    val authorityKeyIdentifier_ASN = ASN1EncodableVector()
    authorityKeyIdentifier_ASN.add(ASN1ObjectIdentifier("2.5.29.35"))
    authorityKeyIdentifier_ASN.add(DEROctetString(akiSeq))
    DERSequence(authorityKeyIdentifier_ASN)
}
