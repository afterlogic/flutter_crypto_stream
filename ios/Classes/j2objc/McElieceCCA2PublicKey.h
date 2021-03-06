//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/McElieceCCA2PublicKey.java
//

#ifndef McElieceCCA2PublicKey_H
#define McElieceCCA2PublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;

@interface LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)n
                              withInt:(jint)t
withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix:(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)g
withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digest;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigest;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getG;

+ (LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *)getInstanceWithId:(id)o;

- (jint)getN;

- (jint)getT;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *self, jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *new_LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *create_LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McElieceCCA2PublicKey_H
