//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/OtherRecipientInfo.java
//

#ifndef OtherRecipientInfo_H
#define OtherRecipientInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmsOtherRecipientInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oriType
                                     withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)oriValue;

+ (LibOrgBouncycastleAsn1CmsOtherRecipientInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                           withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsOtherRecipientInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getType;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsOtherRecipientInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsOtherRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmsOtherRecipientInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oriType, id<LibOrgBouncycastleAsn1ASN1Encodable> oriValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsOtherRecipientInfo *new_LibOrgBouncycastleAsn1CmsOtherRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oriType, id<LibOrgBouncycastleAsn1ASN1Encodable> oriValue) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsOtherRecipientInfo *create_LibOrgBouncycastleAsn1CmsOtherRecipientInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oriType, id<LibOrgBouncycastleAsn1ASN1Encodable> oriValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsOtherRecipientInfo *LibOrgBouncycastleAsn1CmsOtherRecipientInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsOtherRecipientInfo *LibOrgBouncycastleAsn1CmsOtherRecipientInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsOtherRecipientInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OtherRecipientInfo_H