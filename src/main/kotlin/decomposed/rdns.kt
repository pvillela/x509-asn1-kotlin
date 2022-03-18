package decomposed

import org.bouncycastle.asn1.*

///////////////////
//  Relative distinguished names used by other files
//
//  RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

val countryName: DERSet = run {
    val countryNameATV_ASN = ASN1EncodableVector()
    countryNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.6"))
    countryNameATV_ASN.add(DERPrintableString("US"))
    val countryNameATV = DERSequence(countryNameATV_ASN)
    DERSet(countryNameATV)
}

val organizationName: DERSet = run {
    val organizationNameATV_ASN = ASN1EncodableVector()
    organizationNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.10"))
    organizationNameATV_ASN.add(DERPrintableString("Cyberdyne"))
    val organizationNameATV = DERSequence(organizationNameATV_ASN)
    DERSet(organizationNameATV)
}

val organizationalUnitName: DERSet = run {
    val organizationalUnitNameATV_ASN = ASN1EncodableVector()
    organizationalUnitNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.11"))
    organizationalUnitNameATV_ASN.add(DERPrintableString("PKI"))
    val organizationalUnitNameATV = DERSequence(organizationalUnitNameATV_ASN)
    DERSet(organizationalUnitNameATV)
}

val issuerCommonName: DERSet = run {
    val issuerCommonNameATV_ASN = ASN1EncodableVector()
    issuerCommonNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.3"))
    issuerCommonNameATV_ASN.add(DERPrintableString("SecureCA"))
    val issuerCommonNameATV = DERSequence(issuerCommonNameATV_ASN)
    DERSet(issuerCommonNameATV)
}
