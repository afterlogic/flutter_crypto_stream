//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/McEliecePrivateKey.java
//

#ifndef McEliecePrivateKey_H
#define McEliecePrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2mField;
@class LibOrgBouncycastlePqcMathLinearalgebraPermutation;
@class LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM;

@interface LibOrgBouncycastlePqcAsn1McEliecePrivateKey : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)n
                              withInt:(jint)k
withLibOrgBouncycastlePqcMathLinearalgebraGF2mField:(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *)field
withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM:(LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *)goppaPoly
withLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p1
withLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p2
withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix:(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)sInv;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2mField *)getField;

- (LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *)getGoppaPoly;

+ (LibOrgBouncycastlePqcAsn1McEliecePrivateKey *)getInstanceWithId:(id)o;

- (jint)getK;

- (jint)getN;

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)getP1;

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)getP2;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getSInv;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcAsn1McEliecePrivateKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(LibOrgBouncycastlePqcAsn1McEliecePrivateKey *self, jint n, jint k, LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field, LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p1, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p2, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *sInv);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McEliecePrivateKey *new_LibOrgBouncycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint k, LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field, LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p1, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p2, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *sInv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McEliecePrivateKey *create_LibOrgBouncycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint k, LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field, LibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p1, LibOrgBouncycastlePqcMathLinearalgebraPermutation *p2, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *sInv);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McEliecePrivateKey *LibOrgBouncycastlePqcAsn1McEliecePrivateKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcAsn1McEliecePrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McEliecePrivateKey_H
