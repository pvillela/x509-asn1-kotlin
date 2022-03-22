package cert.decomposed

import org.bouncycastle.asn1.*

//=============================================================
//  subject Name
/*
    See Name ASN.1 definition for issuer
 */

val subjectName: DERSequence = run {
    //SubjectName - only need to change the common name
    val subjCommonNameATV_ASN = ASN1EncodableVector()
    subjCommonNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.3"))
    subjCommonNameATV_ASN.add(DERPrintableString("SecureCA"))
    val subjectCommonNameATV = DERSequence(subjCommonNameATV_ASN)

    //RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    val subjectCommonName = DERSet(subjectCommonNameATV)
    val subjectRelativeDistinguishedName = ASN1EncodableVector()
    subjectRelativeDistinguishedName.add(countryName)
    subjectRelativeDistinguishedName.add(organizationName)
    subjectRelativeDistinguishedName.add(organizationalUnitName)
    subjectRelativeDistinguishedName.add(subjectCommonName)

    //RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    DERSequence(subjectRelativeDistinguishedName)
}
