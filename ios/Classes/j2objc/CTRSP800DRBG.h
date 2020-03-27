//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/drbg/CTRSP800DRBG.java
//

#ifndef CTRSP800DRBG_H
#define CTRSP800DRBG_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SP80090DRBG.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoPrngEntropySource;

@interface LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG : NSObject < LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)engine
                                                              withInt:(jint)keySizeInBits
                                                              withInt:(jint)securityStrength
                        withLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource
                                                        withByteArray:(IOSByteArray *)personalizationString
                                                        withByteArray:(IOSByteArray *)nonce;

- (jint)generateWithByteArray:(IOSByteArray *)output
                withByteArray:(IOSByteArray *)additionalInput
                  withBoolean:(jboolean)predictionResistant;

- (jint)getBlockSize;

- (void)reseedWithByteArray:(IOSByteArray *)additionalInput;

#pragma mark Package-Private

- (IOSByteArray *)expandKeyWithByteArray:(IOSByteArray *)key;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG *self, id<LibOrgBouncycastleCryptoBlockCipher> engine, jint keySizeInBits, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG *new_LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<LibOrgBouncycastleCryptoBlockCipher> engine, jint keySizeInBits, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG *create_LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<LibOrgBouncycastleCryptoBlockCipher> engine, jint keySizeInBits, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngDrbgCTRSP800DRBG)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CTRSP800DRBG_H