//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/GF2nPolynomialField.java
//

#ifndef GF2nPolynomialField_H
#define GF2nPolynomialField_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GF2nField.h"
#include "J2ObjC_header.h"

@class IOSIntArray;
@class IOSObjectArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastlePqcMathLinearalgebraGF2nElement;
@class LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial;

@interface LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField : LibOrgBouncycastlePqcMathLinearalgebraGF2nField {
 @public
  IOSObjectArray *squaringMatrix_;
}

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)deg
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (instancetype __nonnull)initWithInt:(jint)deg
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                          withBoolean:(jboolean)file;

- (instancetype __nonnull)initWithInt:(jint)deg
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
withLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:(LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *)polynomial;

- (IOSIntArray *)getPc;

- (LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *)getSquaringVectorWithInt:(jint)i;

- (jint)getTc;

- (jboolean)isPentanomial;

- (jboolean)isTrinomial;

#pragma mark Protected

- (void)computeCOBMatrixWithLibOrgBouncycastlePqcMathLinearalgebraGF2nField:(LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)B1;

- (void)computeFieldPolynomial;

- (void)computeFieldPolynomial2;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)getRandomRootWithLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial:(LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *)polynomial;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField, squaringMatrix_, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random, jboolean file);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(jint deg, JavaSecuritySecureRandom *random, jboolean file) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(jint deg, JavaSecuritySecureRandom *random, jboolean file);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random, LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *polynomial);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_(jint deg, JavaSecuritySecureRandom *random, LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *polynomial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withLibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial_(jint deg, JavaSecuritySecureRandom *random, LibOrgBouncycastlePqcMathLinearalgebraPqcMathGF2Polynomial *polynomial);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraGF2nPolynomialField)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GF2nPolynomialField_H