//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DSTU4145Parameters.java
//

#ifndef DSTU4145Parameters_H
#define DSTU4145Parameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECDomainParameters.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleCryptoParamsDSTU4145Parameters : LibOrgBouncycastleCryptoParamsECDomainParameters

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)ecParameters
                                                                     withByteArray:(IOSByteArray *)dke;

- (IOSByteArray *)getDKE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)arg0
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)arg1
                                           withJavaMathBigInteger:(JavaMathBigInteger *)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)arg0
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)arg1
                                           withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                                           withJavaMathBigInteger:(JavaMathBigInteger *)arg3 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)arg0
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)arg1
                                           withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                                           withJavaMathBigInteger:(JavaMathBigInteger *)arg3
                                                    withByteArray:(IOSByteArray *)arg4 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsDSTU4145Parameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsDSTU4145Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(LibOrgBouncycastleCryptoParamsDSTU4145Parameters *self, LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, IOSByteArray *dke);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSTU4145Parameters *new_LibOrgBouncycastleCryptoParamsDSTU4145Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, IOSByteArray *dke) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsDSTU4145Parameters *create_LibOrgBouncycastleCryptoParamsDSTU4145Parameters_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *ecParameters, IOSByteArray *dke);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsDSTU4145Parameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSTU4145Parameters_H
