//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DLSet.java
//

#ifndef DLSet_H
#define DLSet_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Set.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1DLSet : LibOrgBouncycastleAsn1ASN1Set

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)a;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v;

#pragma mark Package-Private

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)arg0
                                                               withBoolean:(jboolean)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)arg0
                                                                withBoolean:(jboolean)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DLSet)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DLSet_init(LibOrgBouncycastleAsn1DLSet *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *new_LibOrgBouncycastleAsn1DLSet_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *create_LibOrgBouncycastleAsn1DLSet_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1DLSet *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *new_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *create_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1DLSet *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *new_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *create_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(LibOrgBouncycastleAsn1DLSet *self, IOSObjectArray *a);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *new_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DLSet *create_LibOrgBouncycastleAsn1DLSet_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *a);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DLSet)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DLSet_H
