//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/Camellia.java
//

#ifndef Camellia_H
#define Camellia_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseAlgorithmParameterGenerator.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "BaseSecretKeyFactory.h"
#include "BaseWrapCipher.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_header.h"
#include "SymmetricAlgorithmProvider.h"

@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleCryptoModesAEADBlockCipher;
@protocol LibOrgBouncycastleCryptoWrapper;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;
@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_ECB)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                          withBoolean:(jboolean)arg1
                                                              withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)arg0
                                                              withInt:(jint)arg1
                                                              withInt:(jint)arg2
                                                              withInt:(jint)arg3
                                                              withInt:(jint)arg4 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                  withBoolean:(jboolean)arg1
                                                                      withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)arg0
                                                                      withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoModesAEADBlockCipher:(id<LibOrgBouncycastleCryptoModesAEADBlockCipher>)arg0
                                                                   withBoolean:(jboolean)arg1
                                                                       withInt:(jint)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider:(id<LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_CBC)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0
                                                          withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Wrap)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseWrapCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoWrapper:(id<LibOrgBouncycastleCryptoWrapper>)arg0
                                                          withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_RFC3211Wrap)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_GMAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseSecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyFactory)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305 *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305 *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Poly1305KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)keySize;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_initWithInt_(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *self, jint keySize);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_initWithInt_(jint keySize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen_initWithInt_(jint keySize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128 : LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128 *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128 *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen128)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192 : LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192 *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192 *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen192)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256 : LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256 *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256 *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_KeyGen256)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParamGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams : LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (NSString *)engineToString;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_AlgParams)

@interface LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings : LibOrgBouncycastleJcajceProviderSymmetricSymmetricAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCamellia_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Camellia_H
