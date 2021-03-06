//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/PartialHashtree.java
//

#ifndef PartialHashtree_H
#define PartialHashtree_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1TspPartialHashtree : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)values;

- (instancetype __nonnull)initWithByteArray2:(IOSObjectArray *)values;

+ (LibOrgBouncycastleAsn1TspPartialHashtree *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getValues;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspPartialHashtree)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspPartialHashtree *LibOrgBouncycastleAsn1TspPartialHashtree_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray_(LibOrgBouncycastleAsn1TspPartialHashtree *self, IOSByteArray *values);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspPartialHashtree *new_LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray_(IOSByteArray *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspPartialHashtree *create_LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray_(IOSByteArray *values);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray2_(LibOrgBouncycastleAsn1TspPartialHashtree *self, IOSObjectArray *values);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspPartialHashtree *new_LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray2_(IOSObjectArray *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspPartialHashtree *create_LibOrgBouncycastleAsn1TspPartialHashtree_initWithByteArray2_(IOSObjectArray *values);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspPartialHashtree)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PartialHashtree_H
