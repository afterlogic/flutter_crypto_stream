//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/elgamal/ElgamalAlgorithmParametersSpi.java
//

#ifndef ElgamalAlgorithmParametersSpi_H
#define ElgamalAlgorithmParametersSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseAlgorithmParameters.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSClass;
@class LibOrgBouncycastleJceSpecElGamalParameterSpec;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters {
 @public
  LibOrgBouncycastleJceSpecElGamalParameterSpec *currentSpec_;
}

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (IOSByteArray *)engineGetEncoded;

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec;

- (void)engineInitWithByteArray:(IOSByteArray *)params;

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format;

- (NSString *)engineToString;

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi, currentSpec_, LibOrgBouncycastleJceSpecElGamalParameterSpec *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricElgamalElgamalAlgorithmParametersSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ElgamalAlgorithmParametersSpi_H
