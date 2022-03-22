package cert.decomposed

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERUTCTime
import java.util.*

//=============================================================
//  validity Validity
/*
    Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }
    Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
 */

val validity: DERSequence = run {
    val notBefore = DERUTCTime(Date(System.currentTimeMillis()))
    val notAfter = DERUTCTime(Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 30 * 12 * 3))
    val time = ASN1EncodableVector()
    time.add(notBefore)
    time.add(notAfter)
    DERSequence(time)
}
