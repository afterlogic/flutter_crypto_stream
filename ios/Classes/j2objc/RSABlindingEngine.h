//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RSABlindingEngine.java
//

#ifndef RSABlindingEngine_H
#define RSABlindingEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricBlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesRSABlindingEngine : NSObject < LibOrgBouncycastleCryptoAsymmetricBlockCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (jint)getInputBlockSize;

- (jint)getOutputBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)processBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesRSABlindingEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRSABlindingEngine *new_LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRSABlindingEngine *create_LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesRSABlindingEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RSABlindingEngine_H