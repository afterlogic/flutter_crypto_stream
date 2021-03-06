//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUSigningPublicKeyParameters.java
//

#ifndef NTRUSigningPublicKeyParameters_H
#define NTRUSigningPublicKeyParameters_H

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
@class LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters;
@class LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter {
 @public
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h_;
}

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)b
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)params;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)params;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                                  withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)params;

- (jboolean)isEqual:(id)obj;

- (IOSByteArray *)getEncoded;

- (NSUInteger)hash;

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters, h_, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *self, IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *self, JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUSigningPublicKeyParameters_H
