//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ec/JcajceEcKeyPairGeneratorSpi.java
//

#ifndef JcajceEcKeyPairGeneratorSpi_H
#define JcajceEcKeyPairGeneratorSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/KeyPairGenerator.h"

@class JavaSecurityKeyPair;
@class JavaSecuritySecureRandom;
@class JavaSecuritySpecECParameterSpec;
@class LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator;
@class LibOrgBouncycastleCryptoParamsECKeyGenerationParameters;
@class LibOrgBouncycastleJceSpecECNamedCurveSpec;
@class LibOrgBouncycastleJceSpecECParameterSpec;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleJcajceProviderConfigProviderConfiguration;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi : JavaSecurityKeyPairGenerator

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)algorithmName;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_initWithNSString_(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi *self, NSString *algorithmName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC : LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi {
 @public
  LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *param_;
  LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *engine_;
  id ecParams_;
  jint strength_;
  JavaSecuritySecureRandom *random_;
  jboolean initialised_;
  NSString *algorithm_EC_;
  id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration> configuration_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration:(id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)configuration;

- (JavaSecurityKeyPair *)generateKeyPair;

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

#pragma mark Protected

- (LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *)createKeyGenParamsBCWithLibOrgBouncycastleJceSpecECParameterSpec:(LibOrgBouncycastleJceSpecECParameterSpec *)p
                                                                                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)r;

- (LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *)createKeyGenParamsJCEWithJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)p
                                                                                         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)r;

- (LibOrgBouncycastleJceSpecECNamedCurveSpec *)createNamedCurveSpecWithNSString:(NSString *)curveName;

- (void)initializeNamedCurveWithNSString:(NSString *)curveName
            withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, param_, LibOrgBouncycastleCryptoParamsECKeyGenerationParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, engine_, LibOrgBouncycastleCryptoGeneratorsECKeyPairGenerator *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, ecParams_, id)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, algorithm_EC_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC, configuration_, id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_init(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_initWithNSString_withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration_(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *self, NSString *algorithm, id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration> configuration);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_initWithNSString_withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration_(NSString *algorithm, id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration> configuration) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC_initWithNSString_withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration_(NSString *algorithm, id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration> configuration);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA : LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration:(id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA_init(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH : LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration:(id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH_init(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDH)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC : LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration:(id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC_init(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECDHC)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV : LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_EC

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleJcajceProviderConfigProviderConfiguration:(id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV_init(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV *new_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV *create_LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcJcajceEcKeyPairGeneratorSpi_ECMQV)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceEcKeyPairGeneratorSpi_H
