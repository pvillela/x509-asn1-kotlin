package cert.decomposed

import org.bouncycastle.asn1.*

//-------------------------------------------------------------
//  CRL Distribution Points
/*
    -- CRL distribution points extension OID and syntax

    ext-CRLDistributionPoints EXTENSION ::= { SYNTAX
     CRLDistributionPoints IDENTIFIED BY id-ce-cRLDistributionPoints}
    id-ce-cRLDistributionPoints     OBJECT IDENTIFIER  ::=  {id-ce 31}
    CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

    DistributionPoint ::= SEQUENCE {
      distributionPoint       [0] DistributionPointName OPTIONAL,
      reasons                 [1] ReasonFlags OPTIONAL,
      cRLIssuer               [2] GeneralNames OPTIONAL
    }
    --
    --  This is not a requirement in the text, but it seems as if it
    --      should be
    --
    --(WITH COMPONENTS {..., distributionPoint PRESENT} |
    -- WITH COMPONENTS {..., cRLIssuer PRESENT})

    DistributionPointName ::= CHOICE {
      fullName                [0] GeneralNames,
      nameRelativeToCRLIssuer [1] RelativeDistinguishedName
    }

    -- PV: see GeneralNames in `Subject Alternative Names` section above
    -- PV: see RelativeDistinguishedName in `issuer Name` section above

    ReasonFlags ::= BIT STRING {
      unused                  (0),
      keyCompromise           (1),
      cACompromise            (2),
      affiliationChanged      (3),
      superseded              (4),
      cessationOfOperation    (5),
      certificateHold         (6),
      privilegeWithdrawn      (7),
      aACompromise            (8)
    }
 */

val crlDistributionPoints: DERSequence = run {
    val crlDPURL_One = DERTaggedObject(false, 6, DERIA5String("http://crl.somewebsite.com/master.crl"))
    val crlDPURL_One_ASN = ASN1EncodableVector()
    crlDPURL_One_ASN.add(crlDPURL_One)
    val crlDPURL_OneSeq = DERSequence(crlDPURL_One_ASN)

    val crlDPURL_Two = DERTaggedObject(
        false,
        6,
        DERIA5String("ldap://crl.somewebsite.com/cn%3dSecureCA%2cou%3dPKI%2co%3dCyberdyne%2cc%3dUS?certificaterevocationlist;binary")
    )
    val crlDPURL_Two_ASN = ASN1EncodableVector()
    crlDPURL_Two_ASN.add(crlDPURL_Two)
    val crlDPURL_TwoSeq = DERSequence(crlDPURL_Two_ASN)

    val DPName_One = DERTaggedObject(false, 0, crlDPURL_OneSeq)
    val DPName_One_ASN = ASN1EncodableVector()
    DPName_One_ASN.add(DPName_One)
    val DPName_One_Seq = DERSequence(DPName_One_ASN)

    val DPName_Two = DERTaggedObject(false, 0, crlDPURL_TwoSeq)
    val DPName_Two_ASN = ASN1EncodableVector()
    DPName_Two_ASN.add(DPName_Two)
    val DPName_Two_Seq = DERSequence(DPName_Two_ASN)

    val DPOne = DERTaggedObject(false, 0, DPName_One_Seq)
    val DPOne_ASN = ASN1EncodableVector()
    DPOne_ASN.add(DPOne)
    val DistributionPointOne = DERSequence(DPOne_ASN)

    val DPTwo = DERTaggedObject(false, 0, DPName_Two_Seq)
    val DPTwo_ASN = ASN1EncodableVector()
    DPTwo_ASN.add(DPTwo)
    val DistributionPointTwo = DERSequence(DPTwo_ASN)

    val CRLDistributionPoints_ASN = ASN1EncodableVector()
    CRLDistributionPoints_ASN.add(DistributionPointOne)
    CRLDistributionPoints_ASN.add(DistributionPointTwo)
    val CRLDistributionPointsSeq = DERSequence(CRLDistributionPoints_ASN)

    val CRLDP_ASN = ASN1EncodableVector()
    CRLDP_ASN.add(ASN1ObjectIdentifier("2.5.29.31"))
    CRLDP_ASN.add(DEROctetString(CRLDistributionPointsSeq))
    DERSequence(CRLDP_ASN)
}
