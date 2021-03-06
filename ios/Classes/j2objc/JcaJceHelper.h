//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/util/JcaJceHelper.java
//

#ifndef JcaJceHelper_H
#define JcaJceHelper_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

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

@protocol LibOrgBouncycastleJcajceUtilJcaJceHelper < JavaObject >

- (JavaxCryptoCipher *)createCipherWithNSString:(NSString *)algorithm;

- (JavaxCryptoMac *)createMacWithNSString:(NSString *)algorithm;

- (JavaxCryptoKeyAgreement *)createKeyAgreementWithNSString:(NSString *)algorithm;

- (JavaSecurityAlgorithmParameterGenerator *)createAlgorithmParameterGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecurityAlgorithmParameters *)createAlgorithmParametersWithNSString:(NSString *)algorithm;

- (JavaxCryptoKeyGenerator *)createKeyGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecurityKeyFactory *)createKeyFactoryWithNSString:(NSString *)algorithm;

- (JavaxCryptoSecretKeyFactory *)createSecretKeyFactoryWithNSString:(NSString *)algorithm;

- (JavaSecurityKeyPairGenerator *)createKeyPairGeneratorWithNSString:(NSString *)algorithm;

- (JavaSecurityMessageDigest *)createDigestWithNSString:(NSString *)algorithm;

- (JavaSecuritySignature *)createSignatureWithNSString:(NSString *)algorithm;

- (JavaSecurityCertCertificateFactory *)createCertificateFactoryWithNSString:(NSString *)algorithm;

- (JavaSecuritySecureRandom *)createSecureRandomWithNSString:(NSString *)algorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceUtilJcaJceHelper)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceUtilJcaJceHelper)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaJceHelper_H
