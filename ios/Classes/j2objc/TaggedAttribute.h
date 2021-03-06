//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/TaggedAttribute.java
//

#ifndef TaggedAttribute_H
#define TaggedAttribute_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Set;
@class LibOrgBouncycastleAsn1CmcBodyPartID;

@interface LibOrgBouncycastleAsn1CmcTaggedAttribute : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)bodyPartID
                       withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)attrType
                                    withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)attrValues;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getAttrType;

- (LibOrgBouncycastleAsn1ASN1Set *)getAttrValues;

- (LibOrgBouncycastleAsn1CmcBodyPartID *)getBodyPartID;

+ (LibOrgBouncycastleAsn1CmcTaggedAttribute *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcTaggedAttribute)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedAttribute *LibOrgBouncycastleAsn1CmcTaggedAttribute_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcTaggedAttribute_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmcTaggedAttribute *self, LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedAttribute *new_LibOrgBouncycastleAsn1CmcTaggedAttribute_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedAttribute *create_LibOrgBouncycastleAsn1CmcTaggedAttribute_initWithLibOrgBouncycastleAsn1CmcBodyPartID_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *attrType, LibOrgBouncycastleAsn1ASN1Set *attrValues);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcTaggedAttribute)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TaggedAttribute_H
