//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERInteger.java
//

#ifndef DERInteger_H
#define DERInteger_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Integer.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleAsn1DERInteger : LibOrgBouncycastleAsn1ASN1Integer

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)value;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)bytes;

- (instancetype __nonnull)initWithLong:(jlong)value;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
                                withBoolean:(jboolean)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DERInteger)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERInteger_initWithByteArray_(LibOrgBouncycastleAsn1DERInteger *self, IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *new_LibOrgBouncycastleAsn1DERInteger_initWithByteArray_(IOSByteArray *bytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *create_LibOrgBouncycastleAsn1DERInteger_initWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERInteger_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1DERInteger *self, JavaMathBigInteger *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *new_LibOrgBouncycastleAsn1DERInteger_initWithJavaMathBigInteger_(JavaMathBigInteger *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *create_LibOrgBouncycastleAsn1DERInteger_initWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERInteger_initWithLong_(LibOrgBouncycastleAsn1DERInteger *self, jlong value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *new_LibOrgBouncycastleAsn1DERInteger_initWithLong_(jlong value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERInteger *create_LibOrgBouncycastleAsn1DERInteger_initWithLong_(jlong value);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DERInteger)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DERInteger_H
