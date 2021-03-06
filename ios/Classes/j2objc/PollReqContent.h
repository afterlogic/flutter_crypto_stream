//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PollReqContent.java
//

#ifndef PollReqContent_H
#define PollReqContent_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1CmpPollReqContent : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)certReqId;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1IntegerArray:(IOSObjectArray *)certReqIds;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)certReqId;

- (instancetype __nonnull)initWithJavaMathBigIntegerArray:(IOSObjectArray *)certReqIds;

- (IOSObjectArray *)getCertReqIds;

- (IOSObjectArray *)getCertReqIdValues;

+ (LibOrgBouncycastleAsn1CmpPollReqContent *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpPollReqContent)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *LibOrgBouncycastleAsn1CmpPollReqContent_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1CmpPollReqContent *self, LibOrgBouncycastleAsn1ASN1Integer *certReqId);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *new_LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *certReqId) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *create_LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *certReqId);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1IntegerArray_(LibOrgBouncycastleAsn1CmpPollReqContent *self, IOSObjectArray *certReqIds);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *new_LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1IntegerArray_(IOSObjectArray *certReqIds) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *create_LibOrgBouncycastleAsn1CmpPollReqContent_initWithLibOrgBouncycastleAsn1ASN1IntegerArray_(IOSObjectArray *certReqIds);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1CmpPollReqContent *self, JavaMathBigInteger *certReqId);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *new_LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigInteger_(JavaMathBigInteger *certReqId) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *create_LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigInteger_(JavaMathBigInteger *certReqId);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigIntegerArray_(LibOrgBouncycastleAsn1CmpPollReqContent *self, IOSObjectArray *certReqIds);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *new_LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigIntegerArray_(IOSObjectArray *certReqIds) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPollReqContent *create_LibOrgBouncycastleAsn1CmpPollReqContent_initWithJavaMathBigIntegerArray_(IOSObjectArray *certReqIds);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpPollReqContent)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PollReqContent_H
