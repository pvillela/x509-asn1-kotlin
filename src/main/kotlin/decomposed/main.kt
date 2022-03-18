package decomposed

import org.bouncycastle.asn1.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.*

// See Constructing an X.509 Certificate Using ASN.1
// https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/ or
// or the local copy of the article in the project directory.
//
// Block comments using /* ... */ contain ASN.1 schema fragments from
// https://datatracker.ietf.org/doc/html/rfc5912.
fun main() {
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
    //  Create Extensions

    val Extensions_ASN = ASN1EncodableVector()
    Extensions_ASN.add(subjectKeyIdentifier)
    Extensions_ASN.add(authorityKeyIdentifier)
    Extensions_ASN.add(keyUsage)
    Extensions_ASN.add(extendedKeyUsage)
    Extensions_ASN.add(basicConstraints)
    Extensions_ASN.add(certificatePolicies)
    Extensions_ASN.add(subjectAlternativeName)
    Extensions_ASN.add(authorityInformationAccess)
    Extensions_ASN.add(crlDistributionPoints)
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

    val file = File("bin/cert-decomposed.der")
    file.writeBytes(Certificate.getEncoded())
}
