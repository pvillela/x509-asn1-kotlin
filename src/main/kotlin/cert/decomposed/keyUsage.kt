package cert.decomposed

import org.bouncycastle.asn1.*

//-------------------------------------------------------------
//  KeyUsage
/*
    -- key usage extension OID and syntax

    ext-KeyUsage EXTENSION ::= { SYNTAX
        KeyUsage IDENTIFIED BY id-ce-keyUsage }
    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

    KeyUsage ::= BIT STRING {

      digitalSignature        (0),
      nonRepudiation          (1), --  recent editions of X.509 have
                                   --  renamed this bit to
                                   --  contentCommitment
      keyEncipherment         (2),
      dataEncipherment        (3),
      keyAgreement            (4),
      keyCertSign             (5),
      cRLSign                 (6),
      encipherOnly            (7),
      decipherOnly            (8)
    }
 */

val keyUsage: DERSequence = run {
    val digitalSignature = 1 shl 7
    val nonRepudiation = 1 shl 6
    val keyEncipherment = 1 shl 5
    val dataEncipherment = 1 shl 4
    val keyAgreement = 1 shl 3
    val keyCertSign = 1 shl 2
    val cRLSign = 1 shl 1
    val encipherOnly = 1 shl 0
    val decipherOnly = 1 shl 15

    //Set digitalSignature, keyCertSign and cRLSign
    val keyUsageBitString = DERBitString(digitalSignature or keyCertSign or cRLSign)
    val keyUsage_ASN = ASN1EncodableVector()
    keyUsage_ASN.add(ASN1ObjectIdentifier("2.5.29.15"))
    keyUsage_ASN.add(DEROctetString(keyUsageBitString))
    DERSequence(keyUsage_ASN)
}
