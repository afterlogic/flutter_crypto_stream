//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DSAParametersGenerator.java
//

#ifndef DSAParametersGenerator_H
#define DSAParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters;
@class LibOrgBouncycastleCryptoParamsDSAParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (LibOrgBouncycastleCryptoParamsDSAParameters *)generateParameters;

- (void)init__WithLibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters:(LibOrgBouncycastleCryptoParamsDSAParameterGenerationParameters *)params OBJC_METHOD_FAMILY_NONE;

- (void)init__WithInt:(jint)size
              withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsDSAParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSAParametersGenerator_H
