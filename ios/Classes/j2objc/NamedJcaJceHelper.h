//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/util/NamedJcaJceHelper.java
//

#ifndef NamedJcaJceHelper_H
#define NamedJcaJceHelper_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "JcaJceHelper.h"

@class JavaSecurityAlgorithmParameterGenerator;
@class JavaSecurityAlgorithmParameters;
@class JavaSecurityCertCertificateFactory;
@class JavaSecurityKeyFactory;
@class JavaSecurityKeyPairGenerator;
@class JavaSecurityMessageDigest;
@class JavaSecuritySecureRandom;
@class JavaSecuritySignature;
@class JavaxCryptoCipher;
@class JavaxCryptoKeyAgreement;
@class JavaxCryptoKeyGenerator;
@class JavaxCryptoMac;
@class JavaxCryptoSecretKeyFactory;

@interface LibOrgBouncycastleJcajceUtilNamedJcaJceHelper : NSObject < LibOrgBouncycastleJcajceUtilJcaJceHelper > {
 @public
  NSString *providerName_;
}

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)providerName;

- (JavaSecurityAlgorithmParameterGenerator *)createAlgorithmParameterGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecurityAlgorithmParameters *)createAlgorithmParametersWithNSString:(NSString *)algorithm;

- (JavaSecurityCertCertificateFactory *)createCertificateFactoryWithNSString:(NSString *)algorithm;

- (JavaxCryptoCipher *)createCipherWithNSString:(NSString *)algorithm;

- (JavaSecurityMessageDigest *)createDigestWithNSString:(NSString *)algorithm;

- (JavaxCryptoKeyAgreement *)createKeyAgreementWithNSString:(NSString *)algorithm;

- (JavaSecurityKeyFactory *)createKeyFactoryWithNSString:(NSString *)algorithm;

- (JavaxCryptoKeyGenerator *)createKeyGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecurityKeyPairGenerator *)createKeyPairGeneratorWithNSString:(NSString *)algorithm;

- (JavaxCryptoMac *)createMacWithNSString:(NSString *)algorithm;

- (JavaxCryptoSecretKeyFactory *)createSecretKeyFactoryWithNSString:(NSString *)algorithm;

- (JavaSecuritySecureRandom *)createSecureRandomWithNSString:(NSString *)algorithm;

- (JavaSecuritySignature *)createSignatureWithNSString:(NSString *)algorithm;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceUtilNamedJcaJceHelper)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceUtilNamedJcaJceHelper, providerName_, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(LibOrgBouncycastleJcajceUtilNamedJcaJceHelper *self, NSString *providerName);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceUtilNamedJcaJceHelper *new_LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(NSString *providerName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceUtilNamedJcaJceHelper *create_LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(NSString *providerName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceUtilNamedJcaJceHelper)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NamedJcaJceHelper_H
