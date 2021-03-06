//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/QTESLAKeyGenerationParameters.java
//

#ifndef QTESLAKeyGenerationParameters_H
#define QTESLAKeyGenerationParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyGenerationParameters.h"

@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters : LibOrgBouncycastleCryptoKeyGenerationParameters

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)securityCategory
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (jint)getSecurityCategory;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters_initWithInt_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters *self, jint securityCategory, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters *new_LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters_initWithInt_withJavaSecuritySecureRandom_(jint securityCategory, JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters *create_LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters_initWithInt_withJavaSecuritySecureRandom_(jint securityCategory, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyGenerationParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // QTESLAKeyGenerationParameters_H
