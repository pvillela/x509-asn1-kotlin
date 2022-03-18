package decomposed

import org.bouncycastle.asn1.*

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

val basicConstraints: DERSequence = run {
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
    DERSequence(basicConstraintExtension)
}
