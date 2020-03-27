//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT283R1Point.java
//

#include "ECConstants.h"
#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECPoint.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "SecT283R1Point.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcCustomSecSecT283R1Point

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y {
  LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, curve, x, y);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                            withBoolean:(jboolean)withCompression {
  LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, withCompression);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
             withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
        withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                            withBoolean:(jboolean)withCompression {
  LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(self, curve, x, y, zs, withCompression);
  return self;
}

- (LibOrgBouncycastleMathEcECPoint *)detach {
  return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(nil, [self getAffineXCoord], [self getAffineYCoord]);
}

- (LibOrgBouncycastleMathEcECFieldElement *)getYCoord {
  LibOrgBouncycastleMathEcECFieldElement *X = x_;
  LibOrgBouncycastleMathEcECFieldElement *L = y_;
  if ([self isInfinity] || [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X)) isZero]) {
    return L;
  }
  LibOrgBouncycastleMathEcECFieldElement *Y = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L)) addWithLibOrgBouncycastleMathEcECFieldElement:X])) multiplyWithLibOrgBouncycastleMathEcECFieldElement:X];
  LibOrgBouncycastleMathEcECFieldElement *Z = IOSObjectArray_Get(nil_chk(zs_), 0);
  if (![((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z)) isOne]) {
    Y = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Y)) divideWithLibOrgBouncycastleMathEcECFieldElement:Z];
  }
  return Y;
}

- (jboolean)getCompressionYTilde {
  LibOrgBouncycastleMathEcECFieldElement *X = [self getRawXCoord];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X)) isZero]) {
    return false;
  }
  LibOrgBouncycastleMathEcECFieldElement *Y = [self getRawYCoord];
  return [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Y)) testBitZero] != [X testBitZero];
}

- (LibOrgBouncycastleMathEcECPoint *)addWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)b {
  if ([self isInfinity]) {
    return b;
  }
  if ([((LibOrgBouncycastleMathEcECPoint *) nil_chk(b)) isInfinity]) {
    return self;
  }
  LibOrgBouncycastleMathEcECCurve *curve = [self getCurve];
  LibOrgBouncycastleMathEcECFieldElement *X1 = self->x_;
  LibOrgBouncycastleMathEcECFieldElement *X2 = [b getRawXCoord];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X1)) isZero]) {
    if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X2)) isZero]) {
      return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
    }
    return [b addWithLibOrgBouncycastleMathEcECPoint:self];
  }
  LibOrgBouncycastleMathEcECFieldElement *L1 = self->y_;
  LibOrgBouncycastleMathEcECFieldElement *Z1 = IOSObjectArray_Get(nil_chk(self->zs_), 0);
  LibOrgBouncycastleMathEcECFieldElement *L2 = [b getRawYCoord];
  LibOrgBouncycastleMathEcECFieldElement *Z2 = [b getZCoordWithInt:0];
  jboolean Z1IsOne = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z1)) isOne];
  LibOrgBouncycastleMathEcECFieldElement *U2 = X2;
  LibOrgBouncycastleMathEcECFieldElement *S2 = L2;
  if (!Z1IsOne) {
    U2 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(U2)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
    S2 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(S2)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
  }
  jboolean Z2IsOne = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z2)) isOne];
  LibOrgBouncycastleMathEcECFieldElement *U1 = X1;
  LibOrgBouncycastleMathEcECFieldElement *S1 = L1;
  if (!Z2IsOne) {
    U1 = [U1 multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z2];
    S1 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(S1)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z2];
  }
  LibOrgBouncycastleMathEcECFieldElement *A = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(S1)) addWithLibOrgBouncycastleMathEcECFieldElement:S2];
  LibOrgBouncycastleMathEcECFieldElement *B = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(U1)) addWithLibOrgBouncycastleMathEcECFieldElement:U2];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(B)) isZero]) {
    if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(A)) isZero]) {
      return [self twice];
    }
    return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  LibOrgBouncycastleMathEcECFieldElement *X3;
  LibOrgBouncycastleMathEcECFieldElement *L3;
  LibOrgBouncycastleMathEcECFieldElement *Z3;
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X2)) isZero]) {
    LibOrgBouncycastleMathEcECPoint *p = [self normalize];
    X1 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getXCoord];
    LibOrgBouncycastleMathEcECFieldElement *Y1 = [p getYCoord];
    LibOrgBouncycastleMathEcECFieldElement *Y2 = L2;
    LibOrgBouncycastleMathEcECFieldElement *L = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Y1)) addWithLibOrgBouncycastleMathEcECFieldElement:Y2])) divideWithLibOrgBouncycastleMathEcECFieldElement:X1];
    X3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L)) square])) addWithLibOrgBouncycastleMathEcECFieldElement:L])) addWithLibOrgBouncycastleMathEcECFieldElement:X1])) addOne];
    if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X3)) isZero]) {
      return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(curve, X3, [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getB])) sqrt], self->withCompression_);
    }
    LibOrgBouncycastleMathEcECFieldElement *Y3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([L multiplyWithLibOrgBouncycastleMathEcECFieldElement:[((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X1)) addWithLibOrgBouncycastleMathEcECFieldElement:X3]])) addWithLibOrgBouncycastleMathEcECFieldElement:X3])) addWithLibOrgBouncycastleMathEcECFieldElement:Y1];
    L3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Y3)) divideWithLibOrgBouncycastleMathEcECFieldElement:X3])) addWithLibOrgBouncycastleMathEcECFieldElement:X3];
    Z3 = [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) fromBigIntegerWithJavaMathBigInteger:JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE)];
  }
  else {
    B = [B square];
    LibOrgBouncycastleMathEcECFieldElement *AU1 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(A)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:U1];
    LibOrgBouncycastleMathEcECFieldElement *AU2 = [A multiplyWithLibOrgBouncycastleMathEcECFieldElement:U2];
    X3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(AU1)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:AU2];
    if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X3)) isZero]) {
      return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(curve, X3, [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getB])) sqrt], self->withCompression_);
    }
    LibOrgBouncycastleMathEcECFieldElement *ABZ2 = [A multiplyWithLibOrgBouncycastleMathEcECFieldElement:B];
    if (!Z2IsOne) {
      ABZ2 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(ABZ2)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z2];
    }
    L3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(AU2)) addWithLibOrgBouncycastleMathEcECFieldElement:B])) squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:ABZ2 withLibOrgBouncycastleMathEcECFieldElement:[((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L1)) addWithLibOrgBouncycastleMathEcECFieldElement:Z1]];
    Z3 = ABZ2;
    if (!Z1IsOne) {
      Z3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z3)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
    }
  }
  return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(curve, X3, L3, [IOSObjectArray newArrayWithObjects:(id[]){ Z3 } count:1 type:LibOrgBouncycastleMathEcECFieldElement_class_()], self->withCompression_);
}

- (LibOrgBouncycastleMathEcECPoint *)twice {
  if ([self isInfinity]) {
    return self;
  }
  LibOrgBouncycastleMathEcECCurve *curve = [self getCurve];
  LibOrgBouncycastleMathEcECFieldElement *X1 = self->x_;
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X1)) isZero]) {
    return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  LibOrgBouncycastleMathEcECFieldElement *L1 = self->y_;
  LibOrgBouncycastleMathEcECFieldElement *Z1 = IOSObjectArray_Get(nil_chk(self->zs_), 0);
  jboolean Z1IsOne = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z1)) isOne];
  LibOrgBouncycastleMathEcECFieldElement *L1Z1 = Z1IsOne ? L1 : [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L1)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
  LibOrgBouncycastleMathEcECFieldElement *Z1Sq = Z1IsOne ? Z1 : [Z1 square];
  LibOrgBouncycastleMathEcECFieldElement *T = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L1)) square])) addWithLibOrgBouncycastleMathEcECFieldElement:L1Z1])) addWithLibOrgBouncycastleMathEcECFieldElement:Z1Sq];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(T)) isZero]) {
    return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(curve, T, [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getB])) sqrt], withCompression_);
  }
  LibOrgBouncycastleMathEcECFieldElement *X3 = [T square];
  LibOrgBouncycastleMathEcECFieldElement *Z3 = Z1IsOne ? T : [T multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1Sq];
  LibOrgBouncycastleMathEcECFieldElement *X1Z1 = Z1IsOne ? X1 : [X1 multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
  LibOrgBouncycastleMathEcECFieldElement *L3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([X1Z1 squarePlusProductWithLibOrgBouncycastleMathEcECFieldElement:T withLibOrgBouncycastleMathEcECFieldElement:L1Z1])) addWithLibOrgBouncycastleMathEcECFieldElement:X3])) addWithLibOrgBouncycastleMathEcECFieldElement:Z3];
  return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(curve, X3, L3, [IOSObjectArray newArrayWithObjects:(id[]){ Z3 } count:1 type:LibOrgBouncycastleMathEcECFieldElement_class_()], self->withCompression_);
}

- (LibOrgBouncycastleMathEcECPoint *)twicePlusWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)b {
  if ([self isInfinity]) {
    return b;
  }
  if ([((LibOrgBouncycastleMathEcECPoint *) nil_chk(b)) isInfinity]) {
    return [self twice];
  }
  LibOrgBouncycastleMathEcECCurve *curve = [self getCurve];
  LibOrgBouncycastleMathEcECFieldElement *X1 = self->x_;
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X1)) isZero]) {
    return b;
  }
  LibOrgBouncycastleMathEcECFieldElement *X2 = [b getRawXCoord];
  LibOrgBouncycastleMathEcECFieldElement *Z2 = [b getZCoordWithInt:0];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X2)) isZero] || ![((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z2)) isOne]) {
    return [((LibOrgBouncycastleMathEcECPoint *) nil_chk([self twice])) addWithLibOrgBouncycastleMathEcECPoint:b];
  }
  LibOrgBouncycastleMathEcECFieldElement *L1 = self->y_;
  LibOrgBouncycastleMathEcECFieldElement *Z1 = IOSObjectArray_Get(nil_chk(self->zs_), 0);
  LibOrgBouncycastleMathEcECFieldElement *L2 = [b getRawYCoord];
  LibOrgBouncycastleMathEcECFieldElement *X1Sq = [X1 square];
  LibOrgBouncycastleMathEcECFieldElement *L1Sq = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L1)) square];
  LibOrgBouncycastleMathEcECFieldElement *Z1Sq = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z1)) square];
  LibOrgBouncycastleMathEcECFieldElement *L1Z1 = [L1 multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1];
  LibOrgBouncycastleMathEcECFieldElement *T = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(Z1Sq)) addWithLibOrgBouncycastleMathEcECFieldElement:L1Sq])) addWithLibOrgBouncycastleMathEcECFieldElement:L1Z1];
  LibOrgBouncycastleMathEcECFieldElement *A = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L2)) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1Sq])) addWithLibOrgBouncycastleMathEcECFieldElement:L1Sq])) multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:T withLibOrgBouncycastleMathEcECFieldElement:X1Sq withLibOrgBouncycastleMathEcECFieldElement:Z1Sq];
  LibOrgBouncycastleMathEcECFieldElement *X2Z1Sq = [X2 multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1Sq];
  LibOrgBouncycastleMathEcECFieldElement *B = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X2Z1Sq)) addWithLibOrgBouncycastleMathEcECFieldElement:T])) square];
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(B)) isZero]) {
    if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(A)) isZero]) {
      return [b twice];
    }
    return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(A)) isZero]) {
    return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(curve, A, [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) getB])) sqrt], withCompression_);
  }
  LibOrgBouncycastleMathEcECFieldElement *X3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([A square])) multiplyWithLibOrgBouncycastleMathEcECFieldElement:X2Z1Sq];
  LibOrgBouncycastleMathEcECFieldElement *Z3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([A multiplyWithLibOrgBouncycastleMathEcECFieldElement:B])) multiplyWithLibOrgBouncycastleMathEcECFieldElement:Z1Sq];
  LibOrgBouncycastleMathEcECFieldElement *L3 = [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([A addWithLibOrgBouncycastleMathEcECFieldElement:B])) square])) multiplyPlusProductWithLibOrgBouncycastleMathEcECFieldElement:T withLibOrgBouncycastleMathEcECFieldElement:[L2 addOne] withLibOrgBouncycastleMathEcECFieldElement:Z3];
  return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(curve, X3, L3, [IOSObjectArray newArrayWithObjects:(id[]){ Z3 } count:1 type:LibOrgBouncycastleMathEcECFieldElement_class_()], self->withCompression_);
}

- (LibOrgBouncycastleMathEcECPoint *)negate {
  if ([self isInfinity]) {
    return self;
  }
  LibOrgBouncycastleMathEcECFieldElement *X = self->x_;
  if ([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(X)) isZero]) {
    return self;
  }
  LibOrgBouncycastleMathEcECFieldElement *L = self->y_;
  LibOrgBouncycastleMathEcECFieldElement *Z = IOSObjectArray_Get(nil_chk(self->zs_), 0);
  return new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(curve_, X, [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk(L)) addWithLibOrgBouncycastleMathEcECFieldElement:Z], [IOSObjectArray newArrayWithObjects:(id[]){ Z } count:1 type:LibOrgBouncycastleMathEcECFieldElement_class_()], self->withCompression_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElement:withLibOrgBouncycastleMathEcECFieldElementArray:withBoolean:);
  methods[3].selector = @selector(detach);
  methods[4].selector = @selector(getYCoord);
  methods[5].selector = @selector(getCompressionYTilde);
  methods[6].selector = @selector(addWithLibOrgBouncycastleMathEcECPoint:);
  methods[7].selector = @selector(twice);
  methods[8].selector = @selector(twicePlusWithLibOrgBouncycastleMathEcECPoint:);
  methods[9].selector = @selector(negate);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECCurve;LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;", "LLibOrgBouncycastleMathEcECCurve;LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;Z", "LLibOrgBouncycastleMathEcECCurve;LLibOrgBouncycastleMathEcECFieldElement;LLibOrgBouncycastleMathEcECFieldElement;[LLibOrgBouncycastleMathEcECFieldElement;Z", "add", "LLibOrgBouncycastleMathEcECPoint;", "twicePlus" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcCustomSecSecT283R1Point = { "SecT283R1Point", "lib.org.bouncycastle.math.ec.custom.sec", ptrTable, methods, NULL, 7, 0x1, 10, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcCustomSecSecT283R1Point;
}

@end

void LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcCustomSecSecT283R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y) {
  LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, false);
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_, curve, x, y)
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_, curve, x, y)
}

void LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcCustomSecSecT283R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression) {
  LibOrgBouncycastleMathEcECPoint_AbstractF2m_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(self, curve, x, y);
  if ((x == nil) != (y == nil)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Exactly one of the field elements is null");
  }
  self->withCompression_ = withCompression;
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

void LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcCustomSecSecT283R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  LibOrgBouncycastleMathEcECPoint_AbstractF2m_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_(self, curve, x, y, zs);
  self->withCompression_ = withCompression;
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

LibOrgBouncycastleMathEcCustomSecSecT283R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT283R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcCustomSecSecT283R1Point, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcCustomSecSecT283R1Point)