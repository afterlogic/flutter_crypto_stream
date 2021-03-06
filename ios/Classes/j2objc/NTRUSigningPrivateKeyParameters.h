//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUSigningPrivateKeyParameters.java
//

#ifndef NTRUSigningPrivateKeyParameters_H
#define NTRUSigningPrivateKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters;
@class LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis;
@class LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters;
@class LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;
@protocol JavaUtilList;
@protocol LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)b
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params;

- (instancetype __nonnull)initWithJavaUtilList:(id<JavaUtilList>)bases
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *)publicKey;

- (jboolean)isEqual:(id)obj;

- (LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *)getBasisWithInt:(jint)i;

- (IOSByteArray *)getEncoded;

- (LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *)getPublicKey;

- (NSUInteger)hash;

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *self, IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *self, JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaUtilList_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *self, id<JavaUtilList> bases, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *publicKey);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaUtilList_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(id<JavaUtilList> bases, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *publicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaUtilList_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(id<JavaUtilList> bases, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *publicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters)

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis : NSObject {
 @public
  id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f_;
  id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime_;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h_;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params_;
}

#pragma mark Public

- (jboolean)isEqual:(id)obj;

- (NSUInteger)hash;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial:(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)f
                              withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial:(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)fPrime
                              withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                     withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params
                                        withBoolean:(jboolean)include_h;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)os
                         withBoolean:(jboolean)include_h;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis, f_, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis, fPrime_, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis, h_, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis, params_, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *self, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_withBoolean_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *self, JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params, jboolean include_h);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_withBoolean_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params, jboolean include_h) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_withBoolean_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params, jboolean include_h);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUSigningPrivateKeyParameters_H
