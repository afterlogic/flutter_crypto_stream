//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/ElGamalParameterSpec.java
//

#ifndef ElGamalParameterSpec_H
#define ElGamalParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@class JavaMathBigInteger;

@interface LibOrgBouncycastleJceSpecElGamalParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)g;

- (JavaMathBigInteger *)getG;

- (JavaMathBigInteger *)getP;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecElGamalParameterSpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecElGamalParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecElGamalParameterSpec *self, JavaMathBigInteger *p, JavaMathBigInteger *g);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecElGamalParameterSpec *new_LibOrgBouncycastleJceSpecElGamalParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecElGamalParameterSpec *create_LibOrgBouncycastleJceSpecElGamalParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecElGamalParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ElGamalParameterSpec_H
