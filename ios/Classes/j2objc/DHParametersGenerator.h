//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DHParametersGenerator.java
//

#ifndef DHParametersGenerator_H
#define DHParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsDHParameters;

@interface LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoParamsDHParameters *)generateParameters;

- (void)init__WithInt:(jint)size
              withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsDHParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DHParametersGenerator_H