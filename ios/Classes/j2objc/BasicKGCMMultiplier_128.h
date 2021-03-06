//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/BasicKGCMMultiplier_128.java
//

#ifndef BasicKGCMMultiplier_128_H
#define BasicKGCMMultiplier_128_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KGCMMultiplier.h"

@class IOSLongArray;

@interface LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128 : NSObject < LibOrgBouncycastleCryptoModesKgcmKGCMMultiplier >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)init__WithLongArray:(IOSLongArray *)H OBJC_METHOD_FAMILY_NONE;

- (void)multiplyHWithLongArray:(IOSLongArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128_init(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128 *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128 *new_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128 *create_LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKgcmBasicKGCMMultiplier_128)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BasicKGCMMultiplier_128_H
