//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcePBEProtectionRemoverFactory.java
//

#ifndef JcePBEProtectionRemoverFactory_H
#define JcePBEProtectionRemoverFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PBEProtectionRemoverFactory.h"

@class IOSCharArray;
@class JavaSecurityProvider;
@class LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory : NSObject < LibOrgBouncycastleOpenpgpOperatorPBEProtectionRemoverFactory >

#pragma mark Public

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase;

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)passPhrase
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)calculatorProvider;

- (LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *)createDecryptorWithNSString:(NSString *)protection;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *)setProviderWithNSString:(NSString *)providerName;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *self, IOSCharArray *passPhrase);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_(IOSCharArray *passPhrase) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_(IOSCharArray *passPhrase);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *self, IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcePBEProtectionRemoverFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcePBEProtectionRemoverFactory_H
