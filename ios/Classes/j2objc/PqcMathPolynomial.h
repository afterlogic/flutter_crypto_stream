//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/PqcMathPolynomial.java
//

#ifndef PqcMathPolynomial_H
#define PqcMathPolynomial_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;
@class LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;

@protocol LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial < JavaObject >

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2;

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2
                                                                                                                       withInt:(jint)modulus;

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial;

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PqcMathPolynomial_H
