package cert.decomposed

import org.bouncycastle.asn1.ASN1Sequence
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey

//=============================================================
//  subjectPublicKeyInfo SubjectPublicKeyInfo
/*
    SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
 */

val keyPair: KeyPair = run {
    //Generate the 2048-bit RSA Public Key
    val kpGen = KeyPairGenerator.getInstance("RSA")
    kpGen.initialize(2048, random)
    kpGen.generateKeyPair()
}

val subjectPublicKeyInfo: ASN1Sequence = run {
    // KeyPair.public method returns SubjectPublicKeyInfo by default (X.509 format)
    val rsaPubKey: PublicKey = keyPair.public

    // Convert public key bytes (already in SubjectPublicKeyInfo format) to ASN1Sequence
    val rsaPubKeyBytes: ByteArray = rsaPubKey.encoded
    ASN1Sequence.getInstance(rsaPubKeyBytes)
}
