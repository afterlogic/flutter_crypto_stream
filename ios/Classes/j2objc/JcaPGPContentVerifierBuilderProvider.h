//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPContentVerifierBuilderProvider.java
//

#ifndef JcaPGPContentVerifierBuilderProvider_H
#define JcaPGPContentVerifierBuilderProvider_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPContentVerifierBuilderProvider.h"

@class JavaSecurityProvider;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilder;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider >

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilder>)getWithInt:(jint)keyAlgorithm
                                                                     withInt:(jint)hashAlgorithm;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider;

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider *)setProviderWithNSString:(NSString *)providerName;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaPGPContentVerifierBuilderProvider_H
