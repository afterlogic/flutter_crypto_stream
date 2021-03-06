//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/TaggedContentInfo.java
//

#ifndef TaggedContentInfo_H
#define TaggedContentInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmcBodyPartID;
@class LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;

@interface LibOrgBouncycastleAsn1CmcTaggedContentInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)bodyPartID
                      withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)contentInfo;

- (LibOrgBouncycastleAsn1CmcBodyPartID *)getBodyPartID;

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getContentInfo;

+ (LibOrgBouncycastleAsn1CmcTaggedContentInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmcTaggedContentInfo *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcTaggedContentInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcTaggedContentInfo *self, LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedContentInfo *new_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedContentInfo *create_LibOrgBouncycastleAsn1CmcTaggedContentInfo_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *contentInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedContentInfo *LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(id o);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedContentInfo *LibOrgBouncycastleAsn1CmcTaggedContentInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcTaggedContentInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TaggedContentInfo_H
