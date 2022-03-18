package decomposed

import org.bouncycastle.asn1.*

//-------------------------------------------------------------
//  Authority Information Access
/*
    -- authority info access

    ext-AuthorityInfoAccess EXTENSION ::= { SYNTAX
     AuthorityInfoAccessSyntax IDENTIFIED BY
     id-pe-authorityInfoAccess }
    id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

    AuthorityInfoAccessSyntax  ::=
         SEQUENCE SIZE (1..MAX) OF AccessDescription

    AccessDescription  ::=  SEQUENCE {
         accessMethod          OBJECT IDENTIFIER,
         accessLocation        GeneralName  }

    -- PV: see definition of GeneralName in above `Subject Alternative Name` section

    -- PV: from elsewhere in X.509 modules

    -- access descriptor definitions
    id-ad-ocsp         OBJECT IDENTIFIER ::= { id-ad 1 }
    id-ad-caIssuers    OBJECT IDENTIFIER ::= { id-ad 2 }

    id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

    id-pe OBJECT IDENTIFIER  ::=  { id-pkix 1 }

    id-pkix  OBJECT IDENTIFIER  ::=
        {iso(1) identified-organization(3) dod(6) internet(1) security(5)
        mechanisms(5) pkix(7)}
 */

val authorityInformationAccess: DERSequence = run {
    val caIssuers = DERTaggedObject(false, 6, DERIA5String("http://www.somewebsite.com/ca.cer"))
    val ocspURL = DERTaggedObject(false, 6, DERIA5String("http://ocsp.somewebsite.com"))
    val caIssuers_ASN = ASN1EncodableVector()
    caIssuers_ASN.add(ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.2"))
    caIssuers_ASN.add(caIssuers)
    val caIssuersSeq = DERSequence(caIssuers_ASN)
    val ocsp_ASN = ASN1EncodableVector()
    ocsp_ASN.add(ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1"))
    ocsp_ASN.add(ocspURL)
    val ocspSeq = DERSequence(ocsp_ASN)

    val accessSyn_ASN = ASN1EncodableVector()
    accessSyn_ASN.add(caIssuersSeq)
    accessSyn_ASN.add(ocspSeq)
    val AIASyntaxSeq = DERSequence(accessSyn_ASN)

    val AIA_ASN = ASN1EncodableVector()
    AIA_ASN.add(ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1"))
    AIA_ASN.add(DEROctetString(AIASyntaxSeq))
    DERSequence(AIA_ASN)
}
