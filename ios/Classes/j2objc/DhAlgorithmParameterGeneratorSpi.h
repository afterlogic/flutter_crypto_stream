//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/DhAlgorithmParameterGeneratorSpi.java
//

#ifndef DhAlgorithmParameterGeneratorSpi_H
#define DhAlgorithmParameterGeneratorSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseAlgorithmParameterGeneratorSpi.h"
#include "J2ObjC_header.h"

@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseAlgorithmParameterGeneratorSpi {
 @public
  JavaSecuritySecureRandom *random_;
  jint strength_;
}

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParameterGeneratorSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DhAlgorithmParameterGeneratorSpi_H
