import org.bouncycastle.asn1.*
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.util.*

// See Constructing an X.509 Certificate Using ASN.1
// https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/ or
// or the local copy of the article in the project directory.
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

    val Version = DERTaggedObject(true, 0, ASN1Integer(2))

    //=============================================================
    //  serialNumber CertificateSerialNumber
    /*
        CertificateSerialNumber  ::=  INTEGER
     */

    // Replace below with appropriate use of SecureRandom
    val CertificateSerialNumber: ASN1Integer = ASN1Integer(BigInteger.valueOf(Math.abs(Random().nextLong())))

    //=============================================================
    //  signature AlgorithmIdentifier
    /*
        AlgorithmIdentifier  ::=  SEQUENCE  {
            algorithm OBJECT IDENTIFIER,
            parameters ANY DEFINED BY algorithm OPTIONAL  }
     */

    val SignatureAlgorithmIdentifier_ASN: ASN1EncodableVector = ASN1EncodableVector()
    SignatureAlgorithmIdentifier_ASN.add(ASN1ObjectIdentifier("1.2.840.113549.1.1.5"))
    SignatureAlgorithmIdentifier_ASN.add(DERNull.INSTANCE)
    val SignatureAlgorithm: DERSequence = DERSequence(SignatureAlgorithmIdentifier_ASN)

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

    val IssuerRelativeDistinguishedName = ASN1EncodableVector()
    IssuerRelativeDistinguishedName.add(countryName)
    IssuerRelativeDistinguishedName.add(organizationName)
    IssuerRelativeDistinguishedName.add(organizationalUnitName)
    IssuerRelativeDistinguishedName.add(issuerCommonName)

    //RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    val IssuerName = DERSequence(IssuerRelativeDistinguishedName)

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
    val Time = ASN1EncodableVector()
    Time.add(notBefore)
    Time.add(notAfter)
    val Validity = DERSequence(Time)

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
    val SubjectRelativeDistinguishedName = ASN1EncodableVector()
    SubjectRelativeDistinguishedName.add(countryName)
    SubjectRelativeDistinguishedName.add(organizationName)
    SubjectRelativeDistinguishedName.add(organizationalUnitName)
    SubjectRelativeDistinguishedName.add(subjectCommonName)

    //RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    val SubjectName = DERSequence(SubjectRelativeDistinguishedName)

    //=============================================================
    //  subjectPublicKeyInfo SubjectPublicKeyInfo
    /*
        SubjectPublicKeyInfo  ::=  SEQUENCE  {
            algorithm            AlgorithmIdentifier,
            subjectPublicKey     BIT STRING  }
     */

    ///Generate the 2048-bit RSA Public Key  - PublicKey returns SubjectPublicKeyInfo by default (X.509 format)
//    val random: SecureRandom = SecureRandom()
    val kpGen = KeyPairGenerator.getInstance("RSA")
    kpGen.initialize(2048, random)
    val keyPair = kpGen.generateKeyPair()
    val RSAPubKey = keyPair.public

    //Convert public key bytes (in SubjectPublicKeyInfo format) to ASN1Sequence
    val RSAPubKeyBytes = RSAPubKey.encoded
    val SubjectPublicKeyInfo = ASN1Sequence.getInstance(RSAPubKeyBytes)

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

    //-------------------------------------------------------------
    //  Subject Key Identifier
    //  Authority Key Identifier

    //Get the subjectPublicKey from SubjectPublicKeyInfo to calculate the keyIdentifier
    val subjectPublicKey = SubjectPublicKeyInfo.getObjectAt(1).toASN1Primitive() as DERBitString

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
    val KeyUsage = DERSequence(keyUsage_ASN)

    //-------------------------------------------------------------
    //  Extended Key Usage

    val serverAuthEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1")
    val emailProtectionEKU = ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.4")
    val EKU_ASN = ASN1EncodableVector()
    EKU_ASN.add(serverAuthEKU)
    EKU_ASN.add(emailProtectionEKU)
    val EKUSeq = DERSequence(EKU_ASN)

    val ExtendedKeyUsage_ASN = ASN1EncodableVector()
    ExtendedKeyUsage_ASN.add(ASN1ObjectIdentifier("2.5.29.37"))
    ExtendedKeyUsage_ASN.add(DEROctetString(EKUSeq))
    val ExtendedKeyUsage = DERSequence(ExtendedKeyUsage_ASN)

    //-------------------------------------------------------------
    //  Basic Constraints

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
    val directoryName = DERTaggedObject(true, 4, SubjectName) //directoryName explicitly tagged

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
    Extensions_ASN.add(KeyUsage)
    Extensions_ASN.add(ExtendedKeyUsage)
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
    TBSCertificate_ASN.add(Version)
    TBSCertificate_ASN.add(CertificateSerialNumber)
    TBSCertificate_ASN.add(SignatureAlgorithm)
    TBSCertificate_ASN.add(IssuerName)
    TBSCertificate_ASN.add(Validity)
    TBSCertificate_ASN.add(SubjectName)
    TBSCertificate_ASN.add(SubjectPublicKeyInfo)
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
    cert_ASN.add(SignatureAlgorithm)
    cert_ASN.add(signatureValue)
    val Certificate = DERSequence(cert_ASN)

    //=============================================================
    //  Write certificate to file

    val file = File("bin/cert.der")
    file.writeBytes(Certificate.getEncoded())
}
