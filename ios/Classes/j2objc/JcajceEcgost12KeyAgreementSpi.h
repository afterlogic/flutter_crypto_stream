//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost12/JcajceEcgost12KeyAgreementSpi.java
//

#ifndef JcajceEcgost12KeyAgreementSpi_H
#define JcajceEcgost12KeyAgreementSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseAgreementSpi.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoAgreementECVKOAgreement;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol JavaSecurityKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoDerivationFunction;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseAgreementSpi

#pragma mark Protected

- (instancetype __nonnull)initWithNSString:(NSString *)kaAlgorithm
withLibOrgBouncycastleCryptoAgreementECVKOAgreement:(LibOrgBouncycastleCryptoAgreementECVKOAgreement *)agreement
withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf;

- (IOSByteArray *)calcSecret;

- (id<JavaSecurityKey>)engineDoPhaseWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                            withBoolean:(jboolean)lastPhase;

- (void)engineInitWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithJavaSecurityKey:(id<JavaSecurityKey>)key
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

#pragma mark Package-Private

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi *self, NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_initWithNSString_withLibOrgBouncycastleCryptoAgreementECVKOAgreement_withLibOrgBouncycastleCryptoDerivationFunction_(NSString *kaAlgorithm, LibOrgBouncycastleCryptoAgreementECVKOAgreement *agreement, id<LibOrgBouncycastleCryptoDerivationFunction> kdf);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256 : LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleCryptoAgreementECVKOAgreement:(LibOrgBouncycastleCryptoAgreementECVKOAgreement *)arg1
withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256 *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256 *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO256)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512 : LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleCryptoAgreementECVKOAgreement:(LibOrgBouncycastleCryptoAgreementECVKOAgreement *)arg1
withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512 *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512 *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12JcajceEcgost12KeyAgreementSpi_ECVKO512)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceEcgost12KeyAgreementSpi_H
