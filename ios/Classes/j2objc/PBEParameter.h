//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/PBEParameter.java
//

#ifndef PBEParameter_H
#define PBEParameter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1PkcsPBEParameter : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *iterations_;
  LibOrgBouncycastleAsn1ASN1OctetString *salt_;
}

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)salt
                                    withInt:(jint)iterations;

+ (LibOrgBouncycastleAsn1PkcsPBEParameter *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getIterationCount;

- (IOSByteArray *)getSalt;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsPBEParameter)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsPBEParameter, iterations_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1PkcsPBEParameter, salt_, LibOrgBouncycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(LibOrgBouncycastleAsn1PkcsPBEParameter *self, IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPBEParameter *new_LibOrgBouncycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPBEParameter *create_LibOrgBouncycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPBEParameter *LibOrgBouncycastleAsn1PkcsPBEParameter_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsPBEParameter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBEParameter_H
