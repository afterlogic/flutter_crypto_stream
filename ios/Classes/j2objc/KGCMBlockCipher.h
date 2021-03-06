//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/KGCMBlockCipher.java
//

#ifndef KGCMBlockCipher_H
#define KGCMBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AEADBlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoModesKGCMBlockCipher : NSObject < LibOrgBouncycastleCryptoModesAEADBlockCipher >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)dstu7624Engine;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (IOSByteArray *)getMac;

- (jint)getOutputSizeWithInt:(jint)len;

- (id<LibOrgBouncycastleCryptoBlockCipher>)getUnderlyingCipher;

- (jint)getUpdateOutputSizeWithInt:(jint)len;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)processAADByteWithByte:(jbyte)inArg;

- (void)processAADBytesWithByteArray:(IOSByteArray *)inArg
                             withInt:(jint)inOff
                             withInt:(jint)len;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)inLen
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKGCMBlockCipher)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKGCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesKGCMBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> dstu7624Engine);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKGCMBlockCipher *new_LibOrgBouncycastleCryptoModesKGCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> dstu7624Engine) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKGCMBlockCipher *create_LibOrgBouncycastleCryptoModesKGCMBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> dstu7624Engine);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKGCMBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KGCMBlockCipher_H
