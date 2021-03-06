//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dstu/JcajceDstuSignatureSpi.java
//

#ifndef JcajceDstuSignatureSpi_H
#define JcajceDstuSignatureSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCSObjectIdentifiers.h"
#include "X509ObjectIdentifiers.h"
#include "java/security/SignatureSpi.h"

@class IOSByteArray;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi : JavaSecuritySignatureSpi < LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, LibOrgBouncycastleAsn1X509X509ObjectIdentifiers >

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id)engineGetParameterWithNSString:(NSString *)param;

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey;

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey;

- (void)engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params;

- (void)engineSetParameterWithNSString:(NSString *)param
                                withId:(id)value;

- (IOSByteArray *)engineSign;

- (void)engineUpdateWithByte:(jbyte)b;

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len;

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes;

#pragma mark Package-Private

- (IOSByteArray *)expandSboxWithByteArray:(IOSByteArray *)compressed;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceDstuSignatureSpi_H
