//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/AsymmetricCipherKeyPairGenerator.java
//

#ifndef AsymmetricCipherKeyPairGenerator_H
#define AsymmetricCipherKeyPairGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAsymmetricCipherKeyPair;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@protocol LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator < JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

- (LibOrgBouncycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAsymmetricCipherKeyPairGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AsymmetricCipherKeyPairGenerator_H
