//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/xmss/XMSSMTKeyPairGeneratorSpi.java
//

#ifndef XMSSMTKeyPairGeneratorSpi_H
#define XMSSMTKeyPairGeneratorSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/KeyPairGenerator.h"

@class JavaSecurityKeyPair;
@class JavaSecuritySecureRandom;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi : JavaSecurityKeyPairGenerator

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaSecurityKeyPair *)generateKeyPair;

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi_init(LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi *new_LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi *create_LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyPairGeneratorSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // XMSSMTKeyPairGeneratorSpi_H
