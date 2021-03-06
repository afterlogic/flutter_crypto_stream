//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CommitmentTypeIndication.java
//

#ifndef CommitmentTypeIndication_H
#define CommitmentTypeIndication_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;

@interface LibOrgBouncycastleAsn1EsfCommitmentTypeIndication : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)commitmentTypeId;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)commitmentTypeId
                                      withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)commitmentTypeQualifier;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getCommitmentTypeId;

- (LibOrgBouncycastleAsn1ASN1Sequence *)getCommitmentTypeQualifier;

+ (LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EsfCommitmentTypeIndication)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *new_LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *create_LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId, LibOrgBouncycastleAsn1ASN1Sequence *commitmentTypeQualifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *new_LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId, LibOrgBouncycastleAsn1ASN1Sequence *commitmentTypeQualifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *create_LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *commitmentTypeId, LibOrgBouncycastleAsn1ASN1Sequence *commitmentTypeQualifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCommitmentTypeIndication *LibOrgBouncycastleAsn1EsfCommitmentTypeIndication_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EsfCommitmentTypeIndication)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CommitmentTypeIndication_H
