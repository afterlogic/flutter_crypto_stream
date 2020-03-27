//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/GOST3410PublicKeySpec.java
//

#ifndef GOST3410PublicKeySpec_H
#define GOST3410PublicKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/KeySpec.h"

@class JavaMathBigInteger;

@interface LibOrgBouncycastleJceSpecGOST3410PublicKeySpec : NSObject < JavaSecuritySpecKeySpec >

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
                              withJavaMathBigInteger:(JavaMathBigInteger *)p
                              withJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a;

- (JavaMathBigInteger *)getA;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (JavaMathBigInteger *)getY;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecGOST3410PublicKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410PublicKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecGOST3410PublicKeySpec *self, JavaMathBigInteger *y, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410PublicKeySpec *new_LibOrgBouncycastleJceSpecGOST3410PublicKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *y, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410PublicKeySpec *create_LibOrgBouncycastleJceSpecGOST3410PublicKeySpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *y, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecGOST3410PublicKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410PublicKeySpec_H