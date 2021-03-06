//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DEREnumerated.java
//

#ifndef DEREnumerated_H
#define DEREnumerated_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Enumerated.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleAsn1DEREnumerated : LibOrgBouncycastleAsn1ASN1Enumerated

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)value;

- (instancetype __nonnull)initWithInt:(jint)value;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)bytes;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DEREnumerated)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(LibOrgBouncycastleAsn1DEREnumerated *self, IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(IOSByteArray *bytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1DEREnumerated *self, JavaMathBigInteger *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(LibOrgBouncycastleAsn1DEREnumerated *self, jint value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *new_LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(jint value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DEREnumerated *create_LibOrgBouncycastleAsn1DEREnumerated_initWithInt_(jint value);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DEREnumerated)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DEREnumerated_H
