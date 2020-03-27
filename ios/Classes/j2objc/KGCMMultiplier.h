//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/kgcm/KGCMMultiplier.java
//

#ifndef KGCMMultiplier_H
#define KGCMMultiplier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSLongArray;

@protocol LibOrgBouncycastleCryptoModesKgcmKGCMMultiplier < JavaObject >

- (void)init__WithLongArray:(IOSLongArray *)H OBJC_METHOD_FAMILY_NONE;

- (void)multiplyHWithLongArray:(IOSLongArray *)z;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKgcmKGCMMultiplier)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKgcmKGCMMultiplier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KGCMMultiplier_H