//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/DSTU4145ParameterSpec.java
//

#ifndef DSTU4145ParameterSpec_H
#define DSTU4145ParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/ECParameterSpec.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySpecECPoint;
@class JavaSecuritySpecEllipticCurve;
@class LibOrgBouncycastleCryptoParamsECDomainParameters;

@interface LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec : JavaSecuritySpecECParameterSpec

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)parameters;

- (jboolean)isEqual:(id)o;

- (IOSByteArray *)getDKE;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySpecEllipticCurve:(JavaSecuritySpecEllipticCurve *)arg0
                                    withJavaSecuritySpecECPoint:(JavaSecuritySpecECPoint *)arg1
                                         withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                                                        withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *self, LibOrgBouncycastleCryptoParamsECDomainParameters *parameters);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *new_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *create_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSTU4145ParameterSpec_H
