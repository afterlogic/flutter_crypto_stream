//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RC532Engine.java
//

#ifndef RC532Engine_H
#define RC532Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesRC532Engine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesRC532Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRC532Engine_init(LibOrgBouncycastleCryptoEnginesRC532Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRC532Engine *new_LibOrgBouncycastleCryptoEnginesRC532Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRC532Engine *create_LibOrgBouncycastleCryptoEnginesRC532Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesRC532Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RC532Engine_H
