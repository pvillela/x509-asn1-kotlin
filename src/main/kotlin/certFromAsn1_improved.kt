import org.bouncycastle.asn1.*
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.math.BigInteger
import java.security.*
import java.util.*

// See Constructing an X.509 Certificate Using ASN.1
// https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/ or
// or the local copy of the article in the project directory.
//
// Block comments using /* ... */ contain ASN.1 schema fragments from
// https://datatracker.ietf.org/doc/html/rfc5912.
fun main() {

    // Secure random number generator for cert serial number and key generation
    val random: SecureRandom = SecureRandom()

    // The comments immediately below contain the ASN.1 structure of what will be built in this
    // function.

    /*
        Certificate ::= SEQUENCE {
             tbsCertificate TBSCertificate,
             signatureAlgorithm AlgorithmIdentifier,
             signatureValue BIT STRING }
     */

    /*
         TBSCertificate ::= SEQUENCE {
             version [0] EXPLICIT Version DEFAULT v1,
             serialNumber CertificateSerialNumber,
             signature AlgorithmIdentifier,
             issuer Name,
             validity Validity,
             subject Name,
             subjectPublicKeyInfo SubjectPublicKeyInfo,
             issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL,
             subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
             extensions [3] EXPLICIT Extensions OPTIONAL }
     */

    //=============================================================
    //  version [0] EXPLICIT Version DEFAULT v1
    /*
        Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    val version = DERTaggedObject(true, 0, ASN1Integer(2))

    //=============================================================
    //  serialNumber CertificateSerialNumber
    /*
        CertificateSerialNumber  ::=  INTEGER
     */

    // Create 9-byte serial number consistent with RFC5280
    val bytes = ByteArray(9)
    random.nextBytes(bytes)
    val bigInteger = BigInteger(1, bytes)
    val serialNumber: ASN1Integer = ASN1Integer(bigInteger)

    //=============================================================
    //  signature AlgorithmIdentifier
    /*
        AlgorithmIdentifier  ::=  SEQUENCE  {
            algorithm OBJECT IDENTIFIER,
            parameters ANY DEFINED BY algorithm OPTIONAL  }
     */

    val signatureAlgorithmIdentifier_ASN: ASN1EncodableVector = ASN1EncodableVector()
    signatureAlgorithmIdentifier_ASN.add(ASN1ObjectIdentifier("1.2.840.113549.1.1.5"))
    signatureAlgorithmIdentifier_ASN.add(DERNull.INSTANCE)
    val signatureAlgorithm: DERSequence = DERSequence(signatureAlgorithmIdentifier_ASN)

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

    val countryNameATV_ASN = ASN1EncodableVector()
    countryNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.6"))
    countryNameATV_ASN.add(DERPrintableString("US"))
    val countryNameATV = DERSequence(countryNameATV_ASN)

    val organizationNameATV_ASN = ASN1EncodableVector()
    organizationNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.10"))
    organizationNameATV_ASN.add(DERPrintableString("Cyberdyne"))
    val organizationNameATV = DERSequence(organizationNameATV_ASN)

    val organizationalUnitNameATV_ASN = ASN1EncodableVector()
    organizationalUnitNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.11"))
    organizationalUnitNameATV_ASN.add(DERPrintableString("PKI"))
    val organizationalUnitNameATV = DERSequence(organizationalUnitNameATV_ASN)

    val issuerCommonNameATV_ASN = ASN1EncodableVector()
    issuerCommonNameATV_ASN.add(ASN1ObjectIdentifier("2.5.4.3"))
    issuerCommonNameATV_ASN.add(DERPrintableString("SecureCA"))
    val issuerCommonNameATV = DERSequence(issuerCommonNameATV_ASN)

    //RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    val countryName = DERSet(countryNameATV)
    val organizationName = DERSet(organizationNameATV)
    val organizationalUnitName = DERSet(organizationalUnitNameATV)
    val issuerCommonName = DERSet(issuerCommonNameATV)

    val issuerRelativeDistinguishedName = ASN1EncodableVector()
    issuerRelativeDistinguishedName.add(countryName)
    issuerRelativeDistinguishedName.add(organizationName)
    issuerRelativeDistinguishedName.add(organizationalUnitName)
    issuerRelativeDistinguishedName.add(issuerCommonName)

    //RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    val issuerName = DERSequence(issuerRelativeDistinguishedName)

    //=============================================================
    //  validity Validity
    /*
        Validity ::= SEQUENCE {
            notBefore      Time,
            notAfter       Time }
        Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
     */

    val notBefore = DERUTCTime(Date(System.currentTimeMillis()))
    val notAfter = DERUTCTime(Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 30 * 12 * 3))
    val time = ASN1EncodableVector()
    time.add(notBefore)
    time.add(notAfter)
    val validity = DERSequence(time)

    //=============================================================
    //  subject Name
    /*
        See Name ASN.1 definition above for issuer
     */

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
    val subjectName = DERSequence(subjectRelativeDistinguishedName)

    //=============================================================
    //  subjectPublicKeyInfo SubjectPublicKeyInfo
    /*
        SubjectPublicKeyInfo  ::=  SEQUENCE  {
            algorithm            AlgorithmIdentifier,
            subjectPublicKey     BIT STRING  }
     */

    //Generate the 2048-bit RSA Public Key  - PublicKey returns SubjectPublicKeyInfo by default (X.509 format)
    val kpGen = KeyPairGenerator.getInstance("RSA")
    kpGen.initialize(2048, random)
    val keyPair: KeyPair = kpGen.generateKeyPair()
    val rsaPubKey: PublicKey = keyPair.public

    // Convert public key bytes (already in SubjectPublicKeyInfo format) to ASN1Sequence
    val rsaPubKeyBytes: ByteArray = rsaPubKey.encoded
    val subjectPublicKeyInfo: ASN1Sequence = ASN1Sequence.getInstance(rsaPubKeyBytes)

    //=============================================================
    //  issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL,
    //  subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,

    // The above optional elements are not usually implemented.

    //=============================================================
    //  extensions [3] EXPLICIT Extensions OPTIONAL
    //
    //  Subject Key Identifier
    //  Authority Key Identifier
    //  Key Usage
    //  Extended Key Usage
    //  Basic Constraints
    //  Certificate Policies
    //  Subject Alternative Names
    //  Authority Information Access
    //  CRL Distribution Points

    /*
        --  EXTENSION

        --
        --  This class definition is used to describe the association of
        --      object identifier and ASN.1 type structure for extensions
        --
        --  All extensions are prefixed with ext-
        --
        --  &id contains the object identifier for the extension
        --  &ExtnType specifies the ASN.1 type structure for the extension
        --  &Critical contains the set of legal values for the critical field.
        --      This is normally {TRUE|FALSE} but in some instances may be
        --      restricted to just one of these values.
        --

        EXTENSION ::= CLASS {
            &id  OBJECT IDENTIFIER UNIQUE,
            &ExtnType,
            &Critical    BOOLEAN DEFAULT {TRUE | FALSE }
        } WITH SYNTAX {
            SYNTAX &ExtnType IDENTIFIED BY &id
            [CRITICALITY &Critical]
        }

        --  Extensions
        --
        --  Used for a sequence of extensions.
        --
        --  The parameter contains the set of legal extensions that can
        --  occur in this sequence.
        --

        Extensions{EXTENSION:ExtensionSet} ::=
            SEQUENCE SIZE (1..MAX) OF Extension{{ExtensionSet}}

        --  Extension
        --
        --  Used for a single extension
        --
        --  The parameter contains the set of legal extensions that can
        --      occur in this extension.
        --
        --  The restriction on the critical field has been commented out
        --  the authors are not completely sure it is correct.
        --  The restriction could be done using custom code rather than
        --  compiler-generated code, however.
        --

        Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
            extnID      EXTENSION.&id({ExtensionSet}),

            critical    BOOLEAN
            --                     (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                             DEFAULT FALSE,
            extnValue   OCTET STRING (CONTAINING
                        EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
                        --  contains the DER encoding of the ASN.1 value
                        --  corresponding to the extension type identified
                        --  by extnID
            }

        -- PV: from elsewhere in schema

        -- Shared arc for standard certificate and CRL extensions
        id-ce OBJECT IDENTIFIER  ::=  { joint-iso-ccitt(2) ds(5) 29 }
        -- arc for policy qualifier types
        id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
        -- PV
        id-pkix  OBJECT IDENTIFIER  ::=
            {iso(1) identified-organization(3) dod(6) internet(1) security(5)
            mechanisms(5) pkix(7)}
     */

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
     */

    //Get the subjectPublicKey from SubjectPublicKeyInfo to calculate the keyIdentifier
    val subjectPublicKey = subjectPublicKeyInfo.getObjectAt(1).toASN1Primitive() as DERBitString

    //Calculate the keyIdentifier
    // Same core key identifier for both issuer and subject because this is a self-signed cert
    val pubKeyBitStringBytes = subjectPublicKey.bytes
    val sha1: Digest = SHA1Digest()
    val pubKeydigestBytes = ByteArray(sha1.getDigestSize())
    sha1.update(pubKeyBitStringBytes, 0, pubKeyBitStringBytes.size)
    sha1.doFinal(pubKeydigestBytes, 0)
    val keyIdentifier = DEROctetString(pubKeydigestBytes)

    //Subject Key Identifier
    val subjectKeyIdentifier_ASN = ASN1EncodableVector()
    subjectKeyIdentifier_ASN.add(ASN1ObjectIdentifier("2.5.29.14"))
    // Below additional wrapping with OCTET STRING is needed because of the definition
    // of the extnValue field in the above Extension SEQUENCE type.
    subjectKeyIdentifier_ASN.add(DEROctetString(keyIdentifier))
    val subjectKeyIdentifier = DERSequence(subjectKeyIdentifier_ASN)

    //Authority Key Identifier
    val aki = DERTaggedObject(false, 0, keyIdentifier)
    val akiVec = ASN1EncodableVector()
    akiVec.add(aki)
    val akiSeq = DERSequence(akiVec)
    val authorityKeyIdentifier_ASN = ASN1EncodableVector()
    authorityKeyIdentifier_ASN.add(ASN1ObjectIdentifier("2.5.29.35"))
    authorityKeyIdentifier_ASN.add(DEROctetString(akiSeq))
    val authorityKeyIdentifier = DERSequence(authorityKeyIdentifier_ASN)

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
    val keyUsage = DERSequence(keyUsage_ASN)

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

    val serverAuthEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1")
    val emailProtectionEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4")
    val EKU_ASN = ASN1EncodableVector()
    EKU_ASN.add(serverAuthEKU)
    EKU_ASN.add(emailProtectionEKU)
    val EKUSeq = DERSequence(EKU_ASN)

    val extendedKeyUsage_ASN = ASN1EncodableVector()
    extendedKeyUsage_ASN.add(ASN1ObjectIdentifier("2.5.29.37"))
    extendedKeyUsage_ASN.add(DEROctetString(EKUSeq))
    val extendedKeyUsage = DERSequence(extendedKeyUsage_ASN)

    //-------------------------------------------------------------
    //  Basic Constraints
    /*
        -- basic constraints extension OID and syntax

        ext-BasicConstraints EXTENSION ::= { SYNTAX
         BasicConstraints IDENTIFIED BY id-ce-basicConstraints }
        id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

        BasicConstraints ::= SEQUENCE {
          cA                      BOOLEAN DEFAULT FALSE,
          pathLenConstraint       INTEGER (0..MAX) OPTIONAL
        }

        -- basic constraints extension OID and syntax

        ext-BasicConstraints EXTENSION ::= { SYNTAX
         BasicConstraints IDENTIFIED BY id-ce-basicConstraints }
        id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

        BasicConstraints ::= SEQUENCE {
          cA                      BOOLEAN DEFAULT FALSE,
          pathLenConstraint       INTEGER (0..MAX) OPTIONAL
        }
     */

    val isCA: ASN1Boolean = ASN1Boolean.getInstance(ASN1Boolean.TRUE)
    val pathLenConstraint = ASN1Integer(0)
    val basicConstraintStructure_ASN = ASN1EncodableVector()
    basicConstraintStructure_ASN.add(isCA)
    basicConstraintStructure_ASN.add(pathLenConstraint)
    val basicConstraintSeq = DERSequence(basicConstraintStructure_ASN)

    val basicConstraintExtension = ASN1EncodableVector()
    basicConstraintExtension.add(ASN1ObjectIdentifier("2.5.29.19"))
    basicConstraintExtension.add(ASN1Boolean.TRUE) //Mark critical

    basicConstraintExtension.add(DEROctetString(basicConstraintSeq))
    val BasicConstraints = DERSequence(basicConstraintExtension)

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
    val CertificatePolicies = DERSequence(certificatePoliciesExtension)

    //-------------------------------------------------------------
    //  Subject Alternative Name

    val rfc822Name = DERTaggedObject(false, 1, DERIA5String("john.smith@gmail.com"))
    val directoryName = DERTaggedObject(true, 4, subjectName) //directoryName explicitly tagged

    val GeneralNamesVec = ASN1EncodableVector()
    GeneralNamesVec.add(rfc822Name)
    GeneralNamesVec.add(directoryName)
    val GeneralNamesSeq = DERSequence(GeneralNamesVec)

    val subjectAltname_ASN = ASN1EncodableVector()
    subjectAltname_ASN.add(ASN1ObjectIdentifier("2.5.29.17"))
    subjectAltname_ASN.add(DEROctetString(GeneralNamesSeq))
    val SubjectAlternativeName = DERSequence(subjectAltname_ASN)

    //-------------------------------------------------------------
    //  Authority Information Access

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
    val AuthorityInformationAccess = DERSequence(AIA_ASN)

    //-------------------------------------------------------------
    //  CRL Distribution Points

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
    val CRLDistributionPoints = DERSequence(CRLDP_ASN)

    //-------------------------------------------------------------
    //  Create Extensions

    val Extensions_ASN = ASN1EncodableVector()
    Extensions_ASN.add(subjectKeyIdentifier)
    Extensions_ASN.add(authorityKeyIdentifier)
    Extensions_ASN.add(keyUsage)
    Extensions_ASN.add(extendedKeyUsage)
    Extensions_ASN.add(BasicConstraints)
    Extensions_ASN.add(CertificatePolicies)
    Extensions_ASN.add(SubjectAlternativeName)
    Extensions_ASN.add(AuthorityInformationAccess)
    Extensions_ASN.add(CRLDistributionPoints)
    val Extensions = DERSequence(Extensions_ASN)

    val extensions = DERTaggedObject(true, 3, Extensions)

    //=============================================================
    //  TBSCertificate := SEQUENCE

    val TBSCertificate_ASN = ASN1EncodableVector()
    TBSCertificate_ASN.add(version)
    TBSCertificate_ASN.add(serialNumber)
    TBSCertificate_ASN.add(signatureAlgorithm)
    TBSCertificate_ASN.add(issuerName)
    TBSCertificate_ASN.add(validity)
    TBSCertificate_ASN.add(subjectName)
    TBSCertificate_ASN.add(subjectPublicKeyInfo)
    TBSCertificate_ASN.add(extensions)

    val TBSCertificate = DERSequence(TBSCertificate_ASN)

    //=============================================================
    //  Create the signature value

    Security.addProvider(BouncyCastleProvider())

    val TBSCertificateBytes = TBSCertificate.encoded
    val RSAPrivKey = keyPair.private
    val signer: Signature = Signature.getInstance("SHA1WithRSA", "BC")
    signer.initSign(RSAPrivKey)
    signer.update(TBSCertificateBytes)
    val signature: ByteArray = signer.sign()
    val signatureValue = DERBitString(signature)

    //=============================================================
    //  Create the certificate structure

    val cert_ASN = ASN1EncodableVector()
    cert_ASN.add(TBSCertificate)
    cert_ASN.add(signatureAlgorithm)
    cert_ASN.add(signatureValue)
    val Certificate = DERSequence(cert_ASN)

    //=============================================================
    //  Write certificate to file

    val file = File("bin/cert-improved.der")
    file.writeBytes(Certificate.getEncoded())
}
