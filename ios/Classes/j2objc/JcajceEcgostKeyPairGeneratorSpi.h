//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost/JcajceEcgostKeyPairGeneratorSpi.java
//

#ifndef JcajceEcgostKeyPairGeneratorSpi_H
#define JcajceEcgostKeyPairGeneratorSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/KeyPairGenerator.h"

@class JavaSecurityKeyPair;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator;
@class LibOrgBouncycastleCryptoParamsECKeyGenerationParameters;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi : JavaSecurityKeyPairGenerator {
 @public
  id ecParams_;
  LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *engine_;
  NSString *algorithm_JcajceEcgostKeyPairGeneratorSpi_;
  LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *param_;
  jint strength_;
  JavaSecuritySecureRandom *random_;
  jboolean initialised_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaSecurityKeyPair *)generateKeyPair;

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi, ecParams_, id)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi, engine_, LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi, algorithm_JcajceEcgostKeyPairGeneratorSpi_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi, param_, LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostJcajceEcgostKeyPairGeneratorSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceEcgostKeyPairGeneratorSpi_H
