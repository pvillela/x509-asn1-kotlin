package decomposed

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence

//-------------------------------------------------------------
//  Extended Key Usage
/*
    -- extended key usage extension OID and syntax

    ext-ExtKeyUsage EXTENSION ::= { SYNTAX
     ExtKeyUsageSyntax IDENTIFIED BY id-ce-extKeyUsage }
    id-ce-extKeyUsage OBJECT IDENTIFIER ::= {id-ce 37}

    ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

    KeyPurposeId ::= OBJECT IDENTIFIER

    -- permit unspecified key uses

    anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }

    -- extended key usage extension OID and syntax

    ext-ExtKeyUsage EXTENSION ::= { SYNTAX
     ExtKeyUsageSyntax IDENTIFIED BY id-ce-extKeyUsage }
    id-ce-extKeyUsage OBJECT IDENTIFIER ::= {id-ce 37}

    ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

    KeyPurposeId ::= OBJECT IDENTIFIER

    -- extended key purpose OIDs

    id-kp-serverAuth       OBJECT IDENTIFIER ::= { id-kp 1 }
    id-kp-clientAuth       OBJECT IDENTIFIER ::= { id-kp 2 }
    id-kp-codeSigning      OBJECT IDENTIFIER ::= { id-kp 3 }
    id-kp-emailProtection  OBJECT IDENTIFIER ::= { id-kp 4 }
    id-kp-timeStamping     OBJECT IDENTIFIER ::= { id-kp 8 }
    id-kp-OCSPSigning      OBJECT IDENTIFIER ::= { id-kp 9 }
 */

val extendedKeyUsage: DERSequence = run {
    val serverAuthEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1")
    val emailProtectionEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4")
    val EKU_ASN = ASN1EncodableVector()
    EKU_ASN.add(serverAuthEKU)
    EKU_ASN.add(emailProtectionEKU)
    val EKUSeq = DERSequence(EKU_ASN)

    val extendedKeyUsage_ASN = ASN1EncodableVector()
    extendedKeyUsage_ASN.add(ASN1ObjectIdentifier("2.5.29.37"))
    extendedKeyUsage_ASN.add(DEROctetString(EKUSeq))
    DERSequence(extendedKeyUsage_ASN)
}
