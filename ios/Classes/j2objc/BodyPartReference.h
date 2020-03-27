//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/BodyPartReference.java
//

#ifndef BodyPartReference_H
#define BodyPartReference_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmcBodyPartID;
@class LibOrgBouncycastleAsn1CmcBodyPartPath;

@interface LibOrgBouncycastleAsn1CmcBodyPartReference : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcBodyPartID:(LibOrgBouncycastleAsn1CmcBodyPartID *)bodyPartID;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcBodyPartPath:(LibOrgBouncycastleAsn1CmcBodyPartPath *)bodyPartPath;

- (LibOrgBouncycastleAsn1CmcBodyPartID *)getBodyPartID;

- (LibOrgBouncycastleAsn1CmcBodyPartPath *)getBodyPartPath;

+ (LibOrgBouncycastleAsn1CmcBodyPartReference *)getInstanceWithId:(id)obj;

- (jboolean)isBodyPartID;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcBodyPartReference)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartID_(LibOrgBouncycastleAsn1CmcBodyPartReference *self, LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartReference *new_LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartID_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartReference *create_LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartID_(LibOrgBouncycastleAsn1CmcBodyPartID *bodyPartID);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_(LibOrgBouncycastleAsn1CmcBodyPartReference *self, LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartReference *new_LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_(LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartReference *create_LibOrgBouncycastleAsn1CmcBodyPartReference_initWithLibOrgBouncycastleAsn1CmcBodyPartPath_(LibOrgBouncycastleAsn1CmcBodyPartPath *bodyPartPath);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcBodyPartReference *LibOrgBouncycastleAsn1CmcBodyPartReference_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcBodyPartReference)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BodyPartReference_H