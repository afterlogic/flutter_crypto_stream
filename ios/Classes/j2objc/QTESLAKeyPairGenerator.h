//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/QTESLAKeyPairGenerator.java
//

#ifndef QTESLAKeyPairGenerator_H
#define QTESLAKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator_init(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator *new_LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator *create_LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaQTESLAKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // QTESLAKeyPairGenerator_H
