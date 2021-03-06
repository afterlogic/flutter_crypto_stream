//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/HC128.java
//

#ifndef HC128_H
#define HC128_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseKeyGenerator.h"
#include "BaseStreamCipher.h"
#include "IvAlgorithmParameters.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoStreamCipher;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricHC128 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricHC128)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricHC128)

@interface LibOrgBouncycastleJcajceProviderSymmetricHC128_Base : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)arg0
                                                               withInt:(jint)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)arg0
                                                               withInt:(jint)arg1
                                                               withInt:(jint)arg2
                                                               withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricHC128_Base)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricHC128_Base_init(LibOrgBouncycastleJcajceProviderSymmetricHC128_Base *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_Base *new_LibOrgBouncycastleJcajceProviderSymmetricHC128_Base_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_Base *create_LibOrgBouncycastleJcajceProviderSymmetricHC128_Base_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricHC128_Base)

@interface LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricHC128_KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams : LibOrgBouncycastleJcajceProviderSymmetricUtilIvAlgorithmParameters

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (NSString *)engineToString;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams_init(LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams *new_LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams *create_LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricHC128_AlgParams)

@interface LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricHC128_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HC128_H
