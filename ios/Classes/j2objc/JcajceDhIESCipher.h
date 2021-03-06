//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/JcajceDhIESCipher.java
//

#ifndef JcajceDhIESCipher_H
#define JcajceDhIESCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "javax/crypto/CipherSpi.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoEnginesIESEngine;
@protocol JavaSecurityKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher : JavaxCryptoCipherSpi

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)engine;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)engine
                                                                   withInt:(jint)ivLength;

- (IOSByteArray *)engineDoFinalWithByteArray:(IOSByteArray *)input
                                     withInt:(jint)inputOffset
                                     withInt:(jint)inputLen;

- (jint)engineDoFinalWithByteArray:(IOSByteArray *)input
                           withInt:(jint)inputOffset
                           withInt:(jint)inputLength
                     withByteArray:(IOSByteArray *)output
                           withInt:(jint)outputOffset;

- (jint)engineGetBlockSize;

- (IOSByteArray *)engineGetIV;

- (jint)engineGetKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (jint)engineGetOutputSizeWithInt:(jint)inputLen;

- (JavaSecurityAlgorithmParameters *)engineGetParameters;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)engineSpec
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitWithInt:(jint)opmode
      withJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineSetModeWithNSString:(NSString *)mode;

- (void)engineSetPaddingWithNSString:(NSString *)padding;

- (IOSByteArray *)engineUpdateWithByteArray:(IOSByteArray *)input
                                    withInt:(jint)inputOffset
                                    withInt:(jint)inputLen;

- (jint)engineUpdateWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inputOffset
                          withInt:(jint)inputLen
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outputOffset;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *self, LibOrgBouncycastleCryptoEnginesIESEngine *engine);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_(LibOrgBouncycastleCryptoEnginesIESEngine *engine) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_(LibOrgBouncycastleCryptoEnginesIESEngine *engine);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_withInt_(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *self, LibOrgBouncycastleCryptoEnginesIESEngine *engine, jint ivLength);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *engine, jint ivLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_initWithLibOrgBouncycastleCryptoEnginesIESEngine_withInt_(LibOrgBouncycastleCryptoEnginesIESEngine *engine, jint ivLength);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher)

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES : LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0
                                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES_init(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IES)

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC : LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0
                                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC_init(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithDESedeCBC)

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC : LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoEnginesIESEngine:(LibOrgBouncycastleCryptoEnginesIESEngine *)arg0
                                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC_init(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC *new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC *create_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhIESCipher_IESwithAESCBC)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceDhIESCipher_H
