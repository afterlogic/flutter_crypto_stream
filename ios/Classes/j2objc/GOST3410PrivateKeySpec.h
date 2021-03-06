//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/GOST3410PrivateKeySpec.java
//

#ifndef GOST3410PrivateKeySpec_H
#define GOST3410PrivateKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/KeySpec.h"

@class JavaMathBigInteger;

@interface LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec : NSObject < JavaSecuritySpecKeySpec >

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)x
                              withJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a;

- (JavaMathBigInteger *)getA;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (JavaMathBigInteger *)getX;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *self, JavaMathBigInteger *x, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *new_LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *x, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *create_LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *x, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410PrivateKeySpec_H
