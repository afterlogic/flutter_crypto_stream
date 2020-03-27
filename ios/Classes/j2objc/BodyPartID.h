//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/BodyPartID.java
//

#ifndef BodyPartID_H
#define BodyPartID_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1CmcBodyPartID : LibOrgBouncycastleAsn1ASN1Object
@property (readonly, class) jlong bodyIdMax NS_SWIFT_NAME(bodyIdMax);

+ (jlong)bodyIdMax;

#pragma mark Public

- (instancetype __nonnull)initWithLong:(jlong)id_;

- (jlong)getID;

+ (LibOrgBouncycastleAsn1CmcBodyPartID *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcBodyPartID)

inline jlong LibOrgBouncycastleAsn1CmcBodyPartID_get_bodyIdMax(void);
#define LibOrgBouncycastleAsn1CmcBodyPartID_bodyIdMax 4294967295LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmcBodyPartID, bodyIdMax, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcBodyPartID_initWithLong_(LibOrgBouncycastleAsn1CmcBodyPartID *self, jlong id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartID *new_LibOrgBouncycastleAsn1CmcBodyPartID_initWithLong_(jlong id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartID *create_LibOrgBouncycastleAsn1CmcBodyPartID_initWithLong_(jlong id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartID *LibOrgBouncycastleAsn1CmcBodyPartID_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcBodyPartID)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BodyPartID_H