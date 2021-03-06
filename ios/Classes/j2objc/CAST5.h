//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/CAST5.java
//

#ifndef CAST5_H
#define CAST5_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseAlgorithmParameterGenerator.h"
#include "BaseAlgorithmParameters.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSClass;
@class JavaSecurityAlgorithmParameters;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoModesAEADBlockCipher;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;
@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_ECB)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_CBC)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameterGenerator

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (JavaSecurityAlgorithmParameters *)engineGenerateParameters;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)genParamSpec
                                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParamGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseAlgorithmParameters

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (IOSByteArray *)engineGetEncoded;

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format;

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec;

- (void)engineInitWithByteArray:(IOSByteArray *)params;

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format;

- (NSString *)engineToString;

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_AlgParams)

@interface LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricCAST5_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CAST5_H
