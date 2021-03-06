//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/SignerInfo.java
//

#ifndef SignerInfo_H
#define SignerInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1Set;
@class LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1PkcsSignerInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)version_
                withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)issuerAndSerialNumber
                  withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digAlgorithm
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)authenticatedAttributes
                  withLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)digEncryptionAlgorithm
                          withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)encryptedDigest
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)unauthenticatedAttributes;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (LibOrgBouncycastleAsn1ASN1Set *)getAuthenticatedAttributes;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithm;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getDigestEncryptionAlgorithm;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getEncryptedDigest;

+ (LibOrgBouncycastleAsn1PkcsSignerInfo *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *)getIssuerAndSerialNumber;

- (LibOrgBouncycastleAsn1ASN1Set *)getUnauthenticatedAttributes;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsSignerInfo)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignerInfo *LibOrgBouncycastleAsn1PkcsSignerInfo_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1PkcsSignerInfo *self, LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignerInfo *new_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignerInfo *create_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1ASN1Integer *version_, LibOrgBouncycastleAsn1PkcsIssuerAndSerialNumber *issuerAndSerialNumber, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digAlgorithm, LibOrgBouncycastleAsn1ASN1Set *authenticatedAttributes, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *digEncryptionAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *encryptedDigest, LibOrgBouncycastleAsn1ASN1Set *unauthenticatedAttributes);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsSignerInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignerInfo *new_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsSignerInfo *create_LibOrgBouncycastleAsn1PkcsSignerInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsSignerInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignerInfo_H
