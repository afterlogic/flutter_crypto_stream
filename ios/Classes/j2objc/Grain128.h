//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/Grain128.java
//

#ifndef Grain128_H
#define Grain128_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AlgorithmProvider.h"
#include "BaseKeyGenerator.h"
#include "BaseStreamCipher.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoStreamCipher;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderSymmetricGrain128 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricGrain128)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricGrain128)

@interface LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseStreamCipher

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base_init(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base *new_LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base *create_LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Base)

@interface LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen_init(LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen *new_LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen *create_LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricGrain128_KeyGen)

@interface LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings : LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings_init(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings *new_LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings *create_LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricGrain128_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Grain128_H