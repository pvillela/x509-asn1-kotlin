package cert.decomposed

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERTaggedObject

//=============================================================
//  version [0] EXPLICIT Version DEFAULT v1
/*
    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */

val version = DERTaggedObject(true, 0, ASN1Integer(2))
