//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/jpake/JPAKEPrimeOrderGroup.java
//

#ifndef JPAKEPrimeOrderGroup_H
#define JPAKEPrimeOrderGroup_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaMathBigInteger;

@interface LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)g;

- (JavaMathBigInteger *)getG;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)g
                                         withBoolean:(jboolean)skipChecks;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withBoolean_(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, jboolean skipChecks);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withBoolean_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, jboolean skipChecks) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withBoolean_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *g, jboolean skipChecks);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JPAKEPrimeOrderGroup_H