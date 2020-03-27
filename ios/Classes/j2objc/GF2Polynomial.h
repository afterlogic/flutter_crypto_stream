//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/field/GF2Polynomial.java
//

#ifndef GF2Polynomial_H
#define GF2Polynomial_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Polynomial.h"

@class IOSIntArray;

@interface LibOrgBouncycastleMathFieldGF2Polynomial : NSObject < LibOrgBouncycastleMathFieldPolynomial > {
 @public
  IOSIntArray *exponents_;
}

#pragma mark Public

- (jboolean)isEqual:(id)obj;

- (jint)getDegree;

- (IOSIntArray *)getExponentsPresent;

- (NSUInteger)hash;

#pragma mark Package-Private

- (instancetype __nonnull)initWithIntArray:(IOSIntArray *)exponents;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathFieldGF2Polynomial)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathFieldGF2Polynomial, exponents_, IOSIntArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(LibOrgBouncycastleMathFieldGF2Polynomial *self, IOSIntArray *exponents);

FOUNDATION_EXPORT LibOrgBouncycastleMathFieldGF2Polynomial *new_LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(IOSIntArray *exponents) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathFieldGF2Polynomial *create_LibOrgBouncycastleMathFieldGF2Polynomial_initWithIntArray_(IOSIntArray *exponents);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathFieldGF2Polynomial)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GF2Polynomial_H