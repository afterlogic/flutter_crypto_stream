//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUSigningKeyGenerationParameters.java
//

#ifndef NTRUSigningKeyGenerationParameters_H
#define NTRUSigningKeyGenerationParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyGenerationParameters.h"

@class JavaIoInputStream;
@class JavaIoOutputStream;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters : LibOrgBouncycastleCryptoKeyGenerationParameters < NSCopying > {
 @public
  jint N_;
  jint q_;
  jint d_;
  jint d1_;
  jint d2_;
  jint d3_;
  jint B_;
  jdouble beta_;
  jdouble betaSq_;
  jdouble normBound_;
  jdouble normBoundSq_;
  jint signFailTolerance_;
  jdouble keyNormBound_;
  jdouble keyNormBoundSq_;
  jboolean primeCheck_;
  jint basisType_;
  jint bitsF_;
  jboolean sparse_;
  jint keyGenAlg_;
  id<LibOrgBouncycastleCryptoDigest> hashAlg_;
  jint polyType_;
}
@property (readonly, class) jint BASIS_TYPE_STANDARD NS_SWIFT_NAME(BASIS_TYPE_STANDARD);
@property (readonly, class) jint BASIS_TYPE_TRANSPOSE NS_SWIFT_NAME(BASIS_TYPE_TRANSPOSE);
@property (readonly, class) jint KEY_GEN_ALG_RESULTANT NS_SWIFT_NAME(KEY_GEN_ALG_RESULTANT);
@property (readonly, class) jint KEY_GEN_ALG_FLOAT NS_SWIFT_NAME(KEY_GEN_ALG_FLOAT);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *APR2011_439 NS_SWIFT_NAME(APR2011_439);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *APR2011_439_PROD NS_SWIFT_NAME(APR2011_439_PROD);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *APR2011_743 NS_SWIFT_NAME(APR2011_743);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *APR2011_743_PROD NS_SWIFT_NAME(APR2011_743_PROD);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *TEST157 NS_SWIFT_NAME(TEST157);
@property (readonly, class) LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *TEST157_PROD NS_SWIFT_NAME(TEST157_PROD);

+ (jint)BASIS_TYPE_STANDARD;

+ (jint)BASIS_TYPE_TRANSPOSE;

+ (jint)KEY_GEN_ALG_RESULTANT;

+ (jint)KEY_GEN_ALG_FLOAT;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)APR2011_439;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)APR2011_439_PROD;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)APR2011_743;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)APR2011_743_PROD;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)TEST157;

+ (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)TEST157_PROD;

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is;

- (instancetype __nonnull)initWithInt:(jint)N
                              withInt:(jint)q
                              withInt:(jint)d
                              withInt:(jint)B
                              withInt:(jint)basisType
                           withDouble:(jdouble)beta
                           withDouble:(jdouble)normBound
                           withDouble:(jdouble)keyNormBound
                          withBoolean:(jboolean)primeCheck
                          withBoolean:(jboolean)sparse
                              withInt:(jint)keyGenAlg
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)hashAlg;

- (instancetype __nonnull)initWithInt:(jint)N
                              withInt:(jint)q
                              withInt:(jint)d1
                              withInt:(jint)d2
                              withInt:(jint)d3
                              withInt:(jint)B
                              withInt:(jint)basisType
                           withDouble:(jdouble)beta
                           withDouble:(jdouble)normBound
                           withDouble:(jdouble)keyNormBound
                          withBoolean:(jboolean)primeCheck
                          withBoolean:(jboolean)sparse
                              withInt:(jint)keyGenAlg
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)hashAlg;

- (LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)java_clone;

- (jboolean)isEqual:(id)obj;

- (LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)getSigningParameters;

- (NSUInteger)hash;

- (NSString *)description;

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)arg0
                                                   withInt:(jint)arg1 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, hashAlg_, id<LibOrgBouncycastleCryptoDigest>)

inline jint LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_BASIS_TYPE_STANDARD(void);
#define LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_BASIS_TYPE_STANDARD 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, BASIS_TYPE_STANDARD, jint)

inline jint LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_BASIS_TYPE_TRANSPOSE(void);
#define LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_BASIS_TYPE_TRANSPOSE 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, BASIS_TYPE_TRANSPOSE, jint)

inline jint LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_KEY_GEN_ALG_RESULTANT(void);
#define LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_KEY_GEN_ALG_RESULTANT 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, KEY_GEN_ALG_RESULTANT, jint)

inline jint LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_KEY_GEN_ALG_FLOAT(void);
#define LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_KEY_GEN_ALG_FLOAT 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, KEY_GEN_ALG_FLOAT, jint)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_APR2011_439(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_APR2011_439;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, APR2011_439, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_APR2011_439_PROD(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_APR2011_439_PROD;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, APR2011_439_PROD, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_APR2011_743(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_APR2011_743;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, APR2011_743, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_APR2011_743_PROD(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_APR2011_743_PROD;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, APR2011_743_PROD, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_TEST157(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_TEST157;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, TEST157, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

inline LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_get_TEST157_PROD(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_TEST157_PROD;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters, TEST157_PROD, LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *self, jint N, jint q, jint d, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint d, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint d, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *self, jint N, jint q, jint d1, jint d2, jint d3, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint d1, jint d2, jint d3, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithInt_withInt_withInt_withInt_withInt_withInt_withInt_withDouble_withDouble_withDouble_withBoolean_withBoolean_withInt_withLibOrgBouncycastleCryptoDigest_(jint N, jint q, jint d1, jint d2, jint d3, jint B, jint basisType, jdouble beta, jdouble normBound, jdouble keyNormBound, jboolean primeCheck, jboolean sparse, jint keyGenAlg, id<LibOrgBouncycastleCryptoDigest> hashAlg);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithJavaIoInputStream_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *self, JavaIoInputStream *is);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithJavaIoInputStream_(JavaIoInputStream *is) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_initWithJavaIoInputStream_(JavaIoInputStream *is);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUSigningKeyGenerationParameters_H
