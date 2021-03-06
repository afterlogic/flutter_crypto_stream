//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/RSAPrivateKey.java
//

#ifndef RSAPrivateKey_H
#define RSAPrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1PkcsRSAPrivateKey : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)modulus
                              withJavaMathBigInteger:(JavaMathBigInteger *)publicExponent
                              withJavaMathBigInteger:(JavaMathBigInteger *)privateExponent
                              withJavaMathBigInteger:(JavaMathBigInteger *)prime1
                              withJavaMathBigInteger:(JavaMathBigInteger *)prime2
                              withJavaMathBigInteger:(JavaMathBigInteger *)exponent1
                              withJavaMathBigInteger:(JavaMathBigInteger *)exponent2
                              withJavaMathBigInteger:(JavaMathBigInteger *)coefficient;

- (JavaMathBigInteger *)getCoefficient;

- (JavaMathBigInteger *)getExponent1;

- (JavaMathBigInteger *)getExponent2;

+ (LibOrgBouncycastleAsn1PkcsRSAPrivateKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                       withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1PkcsRSAPrivateKey *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getModulus;

- (JavaMathBigInteger *)getPrime1;

- (JavaMathBigInteger *)getPrime2;

- (JavaMathBigInteger *)getPrivateExponent;

- (JavaMathBigInteger *)getPublicExponent;

- (JavaMathBigInteger *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsRSAPrivateKey)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsRSAPrivateKey *LibOrgBouncycastleAsn1PkcsRSAPrivateKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsRSAPrivateKey *LibOrgBouncycastleAsn1PkcsRSAPrivateKey_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsRSAPrivateKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1PkcsRSAPrivateKey *self, JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsRSAPrivateKey *new_LibOrgBouncycastleAsn1PkcsRSAPrivateKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsRSAPrivateKey *create_LibOrgBouncycastleAsn1PkcsRSAPrivateKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsRSAPrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RSAPrivateKey_H
