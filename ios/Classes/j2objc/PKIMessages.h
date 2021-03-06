//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIMessages.java
//

#ifndef PKIMessages_H
#define PKIMessages_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmpPKIMessage;

@interface LibOrgBouncycastleAsn1CmpPKIMessages : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIMessage:(LibOrgBouncycastleAsn1CmpPKIMessage *)msg;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIMessageArray:(IOSObjectArray *)msgs;

+ (LibOrgBouncycastleAsn1CmpPKIMessages *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (IOSObjectArray *)toPKIMessageArray;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpPKIMessages)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIMessages *LibOrgBouncycastleAsn1CmpPKIMessages_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessage_(LibOrgBouncycastleAsn1CmpPKIMessages *self, LibOrgBouncycastleAsn1CmpPKIMessage *msg);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIMessages *new_LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessage_(LibOrgBouncycastleAsn1CmpPKIMessage *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIMessages *create_LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessage_(LibOrgBouncycastleAsn1CmpPKIMessage *msg);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessageArray_(LibOrgBouncycastleAsn1CmpPKIMessages *self, IOSObjectArray *msgs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIMessages *new_LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessageArray_(IOSObjectArray *msgs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIMessages *create_LibOrgBouncycastleAsn1CmpPKIMessages_initWithLibOrgBouncycastleAsn1CmpPKIMessageArray_(IOSObjectArray *msgs);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpPKIMessages)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIMessages_H
