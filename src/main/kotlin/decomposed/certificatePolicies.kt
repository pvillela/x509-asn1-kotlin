package decomposed

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence

//-------------------------------------------------------------
//  Certificate Policies
/*
    -- certificate policies extension OID and syntax

    ext-CertificatePolicies EXTENSION ::= { SYNTAX
     CertificatePolicies IDENTIFIED BY id-ce-certificatePolicies}
    id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }

    CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

    PolicyInformation ::= SEQUENCE {
      policyIdentifier   CertPolicyId,
      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
              PolicyQualifierInfo OPTIONAL }

    CertPolicyId ::= OBJECT IDENTIFIER

    -- PV: omitted schema lines for optional PolicyQualifierInfo
 */

val certificatePolicies: DERSequence = run {
// See article: author found the two below OIDs online (2.16.840.1.101.2 belonging to US DOD)
    val policyIdentifierOne = ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.5")
    val policyIdentifierTwo = ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.18")

    val policyInformationOne_ASN = ASN1EncodableVector()
    policyInformationOne_ASN.add(policyIdentifierOne)
    val policyInformationSeqOne = DERSequence(policyInformationOne_ASN)

    val policyInformationTwo_ASN = ASN1EncodableVector()
    policyInformationTwo_ASN.add(policyIdentifierTwo)
    val policyInformationSeqTwo = DERSequence(policyInformationTwo_ASN)

    val certificatePolicies_ASN = ASN1EncodableVector()
    certificatePolicies_ASN.add(policyInformationSeqOne)
    certificatePolicies_ASN.add(policyInformationSeqTwo)
    val certificatePoliciesSeq = DERSequence(certificatePolicies_ASN)

    val certificatePoliciesExtension = ASN1EncodableVector()
    certificatePoliciesExtension.add(ASN1ObjectIdentifier("2.5.29.32"))
    certificatePoliciesExtension.add(DEROctetString(certificatePoliciesSeq))
    DERSequence(certificatePoliciesExtension)
}
