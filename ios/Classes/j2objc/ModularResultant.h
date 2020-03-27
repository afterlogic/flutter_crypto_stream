//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/ModularResultant.java
//

#ifndef ModularResultant_H
#define ModularResultant_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Resultant.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;

@interface LibOrgBouncycastlePqcMathNtruPolynomialModularResultant : LibOrgBouncycastlePqcMathNtruPolynomialResultant {
 @public
  JavaMathBigInteger *modulus_;
}

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)rho
                                                                   withJavaMathBigInteger:(JavaMathBigInteger *)res
                                                                   withJavaMathBigInteger:(JavaMathBigInteger *)modulus;

+ (LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *)combineRhoWithLibOrgBouncycastlePqcMathNtruPolynomialModularResultant:(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *)modRes1
                                                                       withLibOrgBouncycastlePqcMathNtruPolynomialModularResultant:(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *)modRes2;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)arg0
                                                                   withJavaMathBigInteger:(JavaMathBigInteger *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant, modulus_, JavaMathBigInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruPolynomialModularResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *new_LibOrgBouncycastlePqcMathNtruPolynomialModularResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *create_LibOrgBouncycastlePqcMathNtruPolynomialModularResultant_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *LibOrgBouncycastlePqcMathNtruPolynomialModularResultant_combineRhoWithLibOrgBouncycastlePqcMathNtruPolynomialModularResultant_withLibOrgBouncycastlePqcMathNtruPolynomialModularResultant_(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *modRes1, LibOrgBouncycastlePqcMathNtruPolynomialModularResultant *modRes2);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathNtruPolynomialModularResultant)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ModularResultant_H