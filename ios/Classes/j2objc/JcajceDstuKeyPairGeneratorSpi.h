//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dstu/JcajceDstuKeyPairGeneratorSpi.java
//

#ifndef JcajceDstuKeyPairGeneratorSpi_H
#define JcajceDstuKeyPairGeneratorSpi_H

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

@interface LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi : JavaSecurityKeyPairGenerator {
 @public
  id ecParams_;
  LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *engine_;
  NSString *algorithm_JcajceDstuKeyPairGeneratorSpi_;
  LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *param_;
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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, ecParams_, id)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, engine_, LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, algorithm_JcajceDstuKeyPairGeneratorSpi_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, param_, LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyPairGeneratorSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceDstuKeyPairGeneratorSpi_H
