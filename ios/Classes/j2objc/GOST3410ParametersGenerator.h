//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/GOST3410ParametersGenerator.java
//

#ifndef GOST3410ParametersGenerator_H
#define GOST3410ParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsGOST3410Parameters;

@interface LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoParamsGOST3410Parameters *)generateParameters;

- (void)init__WithInt:(jint)size
              withInt:(jint)typeproc
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsGOST3410ParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410ParametersGenerator_H
