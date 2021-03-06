//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/SEEDEngine.java
//

#ifndef SEEDEngine_H
#define SEEDEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesSEEDEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

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

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesSEEDEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesSEEDEngine_init(LibOrgBouncycastleCryptoEnginesSEEDEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesSEEDEngine *new_LibOrgBouncycastleCryptoEnginesSEEDEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesSEEDEngine *create_LibOrgBouncycastleCryptoEnginesSEEDEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesSEEDEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SEEDEngine_H
