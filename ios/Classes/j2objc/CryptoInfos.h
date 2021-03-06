//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/CryptoInfos.java
//

#ifndef CryptoInfos_H
#define CryptoInfos_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1TspCryptoInfos : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsCmsAttributeArray:(IOSObjectArray *)attrs;

- (IOSObjectArray *)getAttributes;

+ (LibOrgBouncycastleAsn1TspCryptoInfos *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1TspCryptoInfos *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspCryptoInfos)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspCryptoInfos *LibOrgBouncycastleAsn1TspCryptoInfos_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspCryptoInfos *LibOrgBouncycastleAsn1TspCryptoInfos_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspCryptoInfos_initWithLibOrgBouncycastleAsn1CmsCmsAttributeArray_(LibOrgBouncycastleAsn1TspCryptoInfos *self, IOSObjectArray *attrs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspCryptoInfos *new_LibOrgBouncycastleAsn1TspCryptoInfos_initWithLibOrgBouncycastleAsn1CmsCmsAttributeArray_(IOSObjectArray *attrs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspCryptoInfos *create_LibOrgBouncycastleAsn1TspCryptoInfos_initWithLibOrgBouncycastleAsn1CmsCmsAttributeArray_(IOSObjectArray *attrs);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspCryptoInfos)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CryptoInfos_H
