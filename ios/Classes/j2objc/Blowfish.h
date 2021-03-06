//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/Blowfish.java
//

#ifndef Blowfish_H
#define Blowfish_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseBlockCipher.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoBufferedBlockCipher;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleCryptoModesAEADBlockCipher;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;
@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilBlockCipherProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_ECB)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseBlockCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CBC)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_CMAC)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams : LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (NSString *)engineToString;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_AlgParams)

@interface LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricBlowfish_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Blowfish_H
