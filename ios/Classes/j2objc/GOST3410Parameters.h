//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/GOST3410Parameters.java
//

#ifndef GOST3410Parameters_H
#define GOST3410Parameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CipherParameters.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters;

@interface LibOrgBouncycastleCryptoParamsGOST3410Parameters : NSObject < LibOrgBouncycastleCryptoCipherParameters >

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a
withLibOrgBouncycastleCryptoParamsGOST3410ValidationParameters:(LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters *)params;

- (jboolean)isEqual:(id)obj;

- (JavaMathBigInteger *)getA;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters *)getValidationParameters;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsGOST3410Parameters)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoParamsGOST3410Parameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410Parameters *new_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410Parameters *create_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410ValidationParameters_(LibOrgBouncycastleCryptoParamsGOST3410Parameters *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410Parameters *new_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410ValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsGOST3410Parameters *create_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410ValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a, LibOrgBouncycastleCryptoParamsGOST3410ValidationParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsGOST3410Parameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410Parameters_H
