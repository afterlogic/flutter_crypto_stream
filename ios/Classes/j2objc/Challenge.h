//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/Challenge.java
//

#ifndef Challenge_H
#define Challenge_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1CmpChallenge : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)owf
                                                                  withByteArray:(IOSByteArray *)witness
                                                                  withByteArray:(IOSByteArray *)challenge;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)witness
                              withByteArray:(IOSByteArray *)challenge;

- (IOSByteArray *)getChallenge;

+ (LibOrgBouncycastleAsn1CmpChallenge *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getOwf;

- (IOSByteArray *)getWitness;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpChallenge)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpChallenge *LibOrgBouncycastleAsn1CmpChallenge_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(LibOrgBouncycastleAsn1CmpChallenge *self, IOSByteArray *witness, IOSByteArray *challenge);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(IOSByteArray *witness, IOSByteArray *challenge) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(IOSByteArray *witness, IOSByteArray *challenge);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpChallenge)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Challenge_H
