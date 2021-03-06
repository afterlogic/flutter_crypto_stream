//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/EC.java
//

#ifndef EC_H
#define EC_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricAlgorithmProvider.h"
#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEC : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEC)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEC_init(LibOrgBouncycastleJcajceProviderAsymmetricEC *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEC *new_LibOrgBouncycastleJcajceProviderAsymmetricEC_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEC *create_LibOrgBouncycastleJcajceProviderAsymmetricEC_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEC)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings : LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEC_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EC_H
