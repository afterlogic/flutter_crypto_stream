//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CrlValidatedID.java
//

#ifndef CrlValidatedID_H
#define CrlValidatedID_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1EsfCrlIdentifier;
@class LibOrgBouncycastleAsn1EsfOtherHash;

@interface LibOrgBouncycastleAsn1EsfCrlValidatedID : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EsfOtherHash:(LibOrgBouncycastleAsn1EsfOtherHash *)crlHash;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EsfOtherHash:(LibOrgBouncycastleAsn1EsfOtherHash *)crlHash
                          withLibOrgBouncycastleAsn1EsfCrlIdentifier:(LibOrgBouncycastleAsn1EsfCrlIdentifier *)crlIdentifier;

- (LibOrgBouncycastleAsn1EsfOtherHash *)getCrlHash;

- (LibOrgBouncycastleAsn1EsfCrlIdentifier *)getCrlIdentifier;

+ (LibOrgBouncycastleAsn1EsfCrlValidatedID *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EsfCrlValidatedID)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCrlValidatedID *LibOrgBouncycastleAsn1EsfCrlValidatedID_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1EsfOtherHash *crlHash);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfCrlValidatedID *self, LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCrlValidatedID *new_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfCrlValidatedID *create_LibOrgBouncycastleAsn1EsfCrlValidatedID_initWithLibOrgBouncycastleAsn1EsfOtherHash_withLibOrgBouncycastleAsn1EsfCrlIdentifier_(LibOrgBouncycastleAsn1EsfOtherHash *crlHash, LibOrgBouncycastleAsn1EsfCrlIdentifier *crlIdentifier);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EsfCrlValidatedID)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CrlValidatedID_H
