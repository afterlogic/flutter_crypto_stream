//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/ChaCha7539Engine.java
//

#ifndef ChaCha7539Engine_H
#define ChaCha7539Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Salsa20Engine.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoEnginesChaCha7539Engine : LibOrgBouncycastleCryptoEnginesSalsa20Engine

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

#pragma mark Protected

- (void)advanceCounter;

- (void)advanceCounterWithLong:(jlong)diff;

- (void)generateKeyStreamWithByteArray:(IOSByteArray *)output;

- (jlong)getCounter;

- (jint)getNonceSize;

- (void)resetCounter;

- (void)retreatCounter;

- (void)retreatCounterWithLong:(jlong)diff;

- (void)setKeyWithByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)ivBytes;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesChaCha7539Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesChaCha7539Engine_init(LibOrgBouncycastleCryptoEnginesChaCha7539Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesChaCha7539Engine *new_LibOrgBouncycastleCryptoEnginesChaCha7539Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesChaCha7539Engine *create_LibOrgBouncycastleCryptoEnginesChaCha7539Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesChaCha7539Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ChaCha7539Engine_H