//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BERSequence.java
//

#ifndef BERSequence_H
#define BERSequence_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Sequence.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1BERSequence : LibOrgBouncycastleAsn1ASN1Sequence

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)array;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v;

#pragma mark Package-Private

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BERSequence)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERSequence_init(LibOrgBouncycastleAsn1BERSequence *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *new_LibOrgBouncycastleAsn1BERSequence_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *create_LibOrgBouncycastleAsn1BERSequence_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1BERSequence *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *create_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1BERSequence *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *create_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1EncodableVector *v);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(LibOrgBouncycastleAsn1BERSequence *self, IOSObjectArray *array);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *array) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERSequence *create_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(IOSObjectArray *array);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BERSequence)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BERSequence_H
