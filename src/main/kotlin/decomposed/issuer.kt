package decomposed

import org.bouncycastle.asn1.*

//=============================================================
//  issuer Name
/*
    Name ::= CHOICE { rdnSequence  RDNSequence }
    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    AttributeTypeAndValue ::= SEQUENCE {
        type     AttributeType,
        value    AttributeValue }
 */

val issuerName: DERSequence = run {
    val issuerRelativeDistinguishedName = ASN1EncodableVector()
    issuerRelativeDistinguishedName.add(countryName)
    issuerRelativeDistinguishedName.add(organizationName)
    issuerRelativeDistinguishedName.add(organizationalUnitName)
    issuerRelativeDistinguishedName.add(issuerCommonName)

    //RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    DERSequence(issuerRelativeDistinguishedName)
}
