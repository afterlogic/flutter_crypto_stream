//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/KeyGenerationParameters.java
//

#ifndef KeyGenerationParameters_H
#define KeyGenerationParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastleCryptoKeyGenerationParameters : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                   withInt:(jint)strength;

- (JavaSecuritySecureRandom *)getRandom;

- (jint)getStrength;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoKeyGenerationParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(LibOrgBouncycastleCryptoKeyGenerationParameters *self, JavaSecuritySecureRandom *random, jint strength);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoKeyGenerationParameters *new_LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(JavaSecuritySecureRandom *random, jint strength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoKeyGenerationParameters *create_LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(JavaSecuritySecureRandom *random, jint strength);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoKeyGenerationParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyGenerationParameters_H
