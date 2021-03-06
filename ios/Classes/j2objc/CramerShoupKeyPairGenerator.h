//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/CramerShoupKeyPairGenerator.java
//

#ifndef CramerShoupKeyPairGenerator_H
#define CramerShoupKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricCipherKeyPairGenerator.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator : NSObject < LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator >

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init(LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator *new_LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator *create_LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsCramerShoupKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CramerShoupKeyPairGenerator_H
