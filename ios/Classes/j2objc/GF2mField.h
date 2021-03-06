//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/GF2mField.java
//

#ifndef GF2mField_H
#define GF2mField_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastlePqcMathLinearalgebraGF2mField : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)enc;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathLinearalgebraGF2mField:(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *)field;

- (instancetype __nonnull)initWithInt:(jint)degree;

- (instancetype __nonnull)initWithInt:(jint)degree
                              withInt:(jint)poly;

- (jint)addWithInt:(jint)a
           withInt:(jint)b;

- (NSString *)elementToStrWithInt:(jint)a;

- (jboolean)isEqual:(id)other;

- (jint)expWithInt:(jint)a
           withInt:(jint)k;

- (jint)getDegree;

- (IOSByteArray *)getEncoded;

- (jint)getPolynomial;

- (jint)getRandomElementWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (jint)getRandomNonZeroElement;

- (jint)getRandomNonZeroElementWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (NSUInteger)hash;

- (jint)inverseWithInt:(jint)a;

- (jboolean)isElementOfThisFieldWithInt:(jint)e;

- (jint)multWithInt:(jint)a
            withInt:(jint)b;

- (jint)sqRootWithInt:(jint)a;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraGF2mField)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *self, jint degree);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_(jint degree) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_(jint degree);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_withInt_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *self, jint degree, jint poly);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_withInt_(jint degree, jint poly) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithInt_withInt_(jint degree, jint poly);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithByteArray_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *self, IOSByteArray *enc);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithByteArray_(IOSByteArray *enc) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithByteArray_(IOSByteArray *enc);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2mField_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *self, LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *new_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2mField_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraGF2mField *create_LibOrgBouncycastlePqcMathLinearalgebraGF2mField_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2mField_(LibOrgBouncycastlePqcMathLinearalgebraGF2mField *field);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraGF2mField)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GF2mField_H
