//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/DESedeKeyGenerator.java
//

#ifndef DESedeKeyGenerator_H
#define DESedeKeyGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DESKeyGenerator.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator : LibOrgBouncycastleCryptoGeneratorsDESKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)generateKey;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *new_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator *create_LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsDESedeKeyGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DESedeKeyGenerator_H
