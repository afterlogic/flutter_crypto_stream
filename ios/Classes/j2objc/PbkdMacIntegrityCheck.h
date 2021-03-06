//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/PbkdMacIntegrityCheck.java
//

#ifndef PbkdMacIntegrityCheck_H
#define PbkdMacIntegrityCheck_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1PkcsKeyDerivationFunc;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)macAlgorithm
                                withLibOrgBouncycastleAsn1PkcsKeyDerivationFunc:(LibOrgBouncycastleAsn1PkcsKeyDerivationFunc *)pbkdAlgorithm
                                                                  withByteArray:(IOSByteArray *)mac;

+ (LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck *)getInstanceWithId:(id)o;

- (IOSByteArray *)getMac;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getMacAlgorithm;

- (LibOrgBouncycastleAsn1PkcsKeyDerivationFunc *)getPbkdAlgorithm;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1PkcsKeyDerivationFunc_withByteArray_(LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgorithm, LibOrgBouncycastleAsn1PkcsKeyDerivationFunc *pbkdAlgorithm, IOSByteArray *mac);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck *new_LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1PkcsKeyDerivationFunc_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgorithm, LibOrgBouncycastleAsn1PkcsKeyDerivationFunc *pbkdAlgorithm, IOSByteArray *mac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck *create_LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1PkcsKeyDerivationFunc_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *macAlgorithm, LibOrgBouncycastleAsn1PkcsKeyDerivationFunc *pbkdAlgorithm, IOSByteArray *mac);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck *LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BcPbkdMacIntegrityCheck)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PbkdMacIntegrityCheck_H
