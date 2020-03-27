//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/Shacal2Engine.java
//

#ifndef Shacal2Engine_H
#define Shacal2Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesShacal2Engine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)_forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset;

- (void)reset;

- (void)setKeyWithByteArray:(IOSByteArray *)kb;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesShacal2Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesShacal2Engine_init(LibOrgBouncycastleCryptoEnginesShacal2Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesShacal2Engine *new_LibOrgBouncycastleCryptoEnginesShacal2Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesShacal2Engine *create_LibOrgBouncycastleCryptoEnginesShacal2Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesShacal2Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Shacal2Engine_H