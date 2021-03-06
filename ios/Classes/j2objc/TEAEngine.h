//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/TEAEngine.java
//

#ifndef TEAEngine_H
#define TEAEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesTEAEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesTEAEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesTEAEngine_init(LibOrgBouncycastleCryptoEnginesTEAEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesTEAEngine *new_LibOrgBouncycastleCryptoEnginesTEAEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesTEAEngine *create_LibOrgBouncycastleCryptoEnginesTEAEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesTEAEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TEAEngine_H
