//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/CipherKeyGenerator.java
//

#ifndef CipherKeyGenerator_H
#define CipherKeyGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoKeyGenerationParameters;

@interface LibOrgBouncycastleCryptoCipherKeyGenerator : NSObject {
 @public
  JavaSecuritySecureRandom *random_;
  jint strength_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)generateKey;

- (void)init__WithLibOrgBouncycastleCryptoKeyGenerationParameters:(LibOrgBouncycastleCryptoKeyGenerationParameters *)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoCipherKeyGenerator)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoCipherKeyGenerator, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoCipherKeyGenerator_init(LibOrgBouncycastleCryptoCipherKeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoCipherKeyGenerator *new_LibOrgBouncycastleCryptoCipherKeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoCipherKeyGenerator *create_LibOrgBouncycastleCryptoCipherKeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoCipherKeyGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CipherKeyGenerator_H
