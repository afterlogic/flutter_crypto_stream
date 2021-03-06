//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/NullEngine.java
//

#ifndef NullEngine_H
#define NullEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesNullEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >
@property (readonly, class) jint DEFAULT_BLOCK_SIZE NS_SWIFT_NAME(DEFAULT_BLOCK_SIZE);

+ (jint)DEFAULT_BLOCK_SIZE;

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)blockSize;

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesNullEngine)

inline jint LibOrgBouncycastleCryptoEnginesNullEngine_get_DEFAULT_BLOCK_SIZE(void);
#define LibOrgBouncycastleCryptoEnginesNullEngine_DEFAULT_BLOCK_SIZE 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesNullEngine, DEFAULT_BLOCK_SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesNullEngine_init(LibOrgBouncycastleCryptoEnginesNullEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesNullEngine *new_LibOrgBouncycastleCryptoEnginesNullEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesNullEngine *create_LibOrgBouncycastleCryptoEnginesNullEngine_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesNullEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesNullEngine *self, jint blockSize);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesNullEngine *new_LibOrgBouncycastleCryptoEnginesNullEngine_initWithInt_(jint blockSize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesNullEngine *create_LibOrgBouncycastleCryptoEnginesNullEngine_initWithInt_(jint blockSize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesNullEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NullEngine_H
