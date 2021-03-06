//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ess/ESSCertIDv2.java
//

#ifndef ESSCertIDv2_H
#define ESSCertIDv2_H

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
@class LibOrgBouncycastleAsn1X509IssuerSerial;

@interface LibOrgBouncycastleAsn1EssESSCertIDv2 : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                                  withByteArray:(IOSByteArray *)certHash;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algId
                                                                  withByteArray:(IOSByteArray *)certHash
                                     withLibOrgBouncycastleAsn1X509IssuerSerial:(LibOrgBouncycastleAsn1X509IssuerSerial *)issuerSerial;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)certHash;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)certHash
 withLibOrgBouncycastleAsn1X509IssuerSerial:(LibOrgBouncycastleAsn1X509IssuerSerial *)issuerSerial;

- (IOSByteArray *)getCertHash;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm;

+ (LibOrgBouncycastleAsn1EssESSCertIDv2 *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1X509IssuerSerial *)getIssuerSerial;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1EssESSCertIDv2)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *LibOrgBouncycastleAsn1EssESSCertIDv2_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_(LibOrgBouncycastleAsn1EssESSCertIDv2 *self, IOSByteArray *certHash);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *new_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_(IOSByteArray *certHash) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *create_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_(IOSByteArray *certHash);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1EssESSCertIDv2 *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *new_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *create_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1EssESSCertIDv2 *self, IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *new_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *create_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1EssESSCertIDv2 *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *new_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertIDv2 *create_LibOrgBouncycastleAsn1EssESSCertIDv2_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algId, IOSByteArray *certHash, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EssESSCertIDv2)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ESSCertIDv2_H
