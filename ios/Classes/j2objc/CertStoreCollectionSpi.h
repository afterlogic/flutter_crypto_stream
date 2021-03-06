//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/CertStoreCollectionSpi.java
//

#ifndef CertStoreCollectionSpi_H
#define CertStoreCollectionSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/CertStoreSpi.h"

@protocol JavaSecurityCertCRLSelector;
@protocol JavaSecurityCertCertSelector;
@protocol JavaSecurityCertCertStoreParameters;
@protocol JavaUtilCollection;

@interface LibOrgBouncycastleJceProviderCertStoreCollectionSpi : JavaSecurityCertCertStoreSpi

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecurityCertCertStoreParameters:(id<JavaSecurityCertCertStoreParameters>)params;

- (id<JavaUtilCollection>)engineGetCertificatesWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)selector;

- (id<JavaUtilCollection>)engineGetCRLsWithJavaSecurityCertCRLSelector:(id<JavaSecurityCertCRLSelector>)selector;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderCertStoreCollectionSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderCertStoreCollectionSpi_initWithJavaSecurityCertCertStoreParameters_(LibOrgBouncycastleJceProviderCertStoreCollectionSpi *self, id<JavaSecurityCertCertStoreParameters> params);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderCertStoreCollectionSpi *new_LibOrgBouncycastleJceProviderCertStoreCollectionSpi_initWithJavaSecurityCertCertStoreParameters_(id<JavaSecurityCertCertStoreParameters> params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderCertStoreCollectionSpi *create_LibOrgBouncycastleJceProviderCertStoreCollectionSpi_initWithJavaSecurityCertCertStoreParameters_(id<JavaSecurityCertCertStoreParameters> params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderCertStoreCollectionSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertStoreCollectionSpi_H
