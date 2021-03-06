//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPKeyPair.java
//

#ifndef JcaPGPKeyPair_H
#define JcaPGPKeyPair_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPKeyPair.h"

@class JavaSecurityKeyPair;
@class JavaUtilDate;
@class LibOrgBouncycastleOpenpgpPGPPrivateKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@protocol LibOrgBouncycastleOpenpgpPGPAlgorithmParameters;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair : LibOrgBouncycastleOpenpgpPGPKeyPair

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)algorithm
              withJavaSecurityKeyPair:(JavaSecurityKeyPair *)keyPair
                     withJavaUtilDate:(JavaUtilDate *)date;

- (instancetype __nonnull)initWithInt:(jint)algorithm
withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters:(id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters>)parameters
              withJavaSecurityKeyPair:(JavaSecurityKeyPair *)keyPair
                     withJavaUtilDate:(JavaUtilDate *)date;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)arg0
                             withLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *self, jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, JavaSecurityKeyPair *keyPair, JavaUtilDate *date);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *self, jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withLibOrgBouncycastleOpenpgpPGPAlgorithmParameters_withJavaSecurityKeyPair_withJavaUtilDate_(jint algorithm, id<LibOrgBouncycastleOpenpgpPGPAlgorithmParameters> parameters, JavaSecurityKeyPair *keyPair, JavaUtilDate *date);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaPGPKeyPair_H
