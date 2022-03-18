package decomposed

import org.bouncycastle.asn1.*

//-------------------------------------------------------------
//  Subject Alternative Name
/*
    -- subject alternative name extension OID and syntax

    ext-SubjectAltName EXTENSION ::= { SYNTAX
     GeneralNames IDENTIFIED BY id-ce-subjectAltName }
    id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

    GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

    GeneralName ::= CHOICE {
      otherName                   [0]  INSTANCE OF OTHER-NAME,
      rfc822Name                  [1]  IA5String,
      dNSName                     [2]  IA5String,
      x400Address                 [3]  ORAddress,
      directoryName               [4]  Name,
      ediPartyName                [5]  EDIPartyName,
      uniformResourceIdentifier   [6]  IA5String,
      iPAddress                   [7]  OCTET STRING,
      registeredID                [8]  OBJECT IDENTIFIER
    }

    -- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
    -- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax

    OTHER-NAME ::= TYPE-IDENTIFIER

    -- PV: see definition of Name in `issuer Name` section above
    -- PV: omitted schema lines for CHOICE options not used here
 */

val subjectAlternativeName: DERSequence = run {
    val rfc822Name = DERTaggedObject(false, 1, DERIA5String("john.smith@gmail.com"))
    val directoryName = DERTaggedObject(true, 4, subjectName) //directoryName explicitly tagged

    val GeneralNamesVec = ASN1EncodableVector()
    GeneralNamesVec.add(rfc822Name)
    GeneralNamesVec.add(directoryName)
    val GeneralNamesSeq = DERSequence(GeneralNamesVec)

    val subjectAltname_ASN = ASN1EncodableVector()
    subjectAltname_ASN.add(ASN1ObjectIdentifier("2.5.29.17"))
    subjectAltname_ASN.add(DEROctetString(GeneralNamesSeq))
    DERSequence(subjectAltname_ASN)
}
