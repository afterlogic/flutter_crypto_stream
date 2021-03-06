//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/PSSSignatureSpi.java
//

#ifndef PSSSignatureSpi_H
#define PSSSignatureSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/SignatureSpi.h"

@class IOSByteArray;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class JavaSecuritySpecPSSParameterSpec;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoAsymmetricBlockCipher;

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi : JavaSecuritySignatureSpi

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)signer
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)paramSpecArg;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)signer
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)baseParamSpec
                                                                    withBoolean:(jboolean)isRaw;

- (id)engineGetParameterWithNSString:(NSString *)param;

- (JavaSecurityAlgorithmParameters *)engineGetParameters;

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey;

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey
                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey;

- (void)engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params;

- (void)engineSetParameterWithNSString:(NSString *)param
                                withId:(id)value;

- (IOSByteArray *)engineSign;

- (void)engineUpdateWithByte:(jbyte)b;

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len;

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *paramSpecArg);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *paramSpecArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *paramSpecArg);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_withBoolean_(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *baseParamSpec, jboolean isRaw);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *baseParamSpec, jboolean isRaw) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withJavaSecuritySpecPSSParameterSpec_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> signer, JavaSecuritySpecPSSParameterSpec *baseParamSpec, jboolean isRaw);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_nonePSS)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_PSSwithRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA1withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA224withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA256withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA384withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_224withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA512_256withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_224withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_256withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_384withRSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA : LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)arg0
                                           withJavaSecuritySpecPSSParameterSpec:(JavaSecuritySpecPSSParameterSpec *)arg1
                                                                    withBoolean:(jboolean)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaPSSSignatureSpi_SHA3_512withRSA)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PSSSignatureSpi_H
