//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McEliecePKCSCipherSpi.java
//

#ifndef McEliecePKCSCipherSpi_H
#define McEliecePKCSCipherSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCSObjectIdentifiers.h"
#include "PqcAsymmetricBlockCipher.h"
#include "X509ObjectIdentifiers.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher;
@protocol JavaSecurityKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi : LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher < LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, LibOrgBouncycastleAsn1X509X509ObjectIdentifiers >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher:(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher *)cipher;

- (jint)getKeySizeWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (NSString *)getName;

#pragma mark Protected

- (void)initCipherDecryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
  withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params OBJC_METHOD_FAMILY_NONE;

- (void)initCipherEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
  withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)messageDecryptWithByteArray:(IOSByteArray *)input;

- (IOSByteArray *)messageEncryptWithByteArray:(IOSByteArray *)input;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher_(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi *self, LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher *cipher);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher *cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher *cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi)

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS : LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher:(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCipher *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcEliecePKCSCipherSpi_McEliecePKCS)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McEliecePKCSCipherSpi_H