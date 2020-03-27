//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/ECParameterSpec.java
//

#ifndef ECParameterSpec_H
#define ECParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleJceSpecECParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)G
                                           withJavaMathBigInteger:(JavaMathBigInteger *)n;

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)G
                                           withJavaMathBigInteger:(JavaMathBigInteger *)n
                                           withJavaMathBigInteger:(JavaMathBigInteger *)h;

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                              withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)G
                                           withJavaMathBigInteger:(JavaMathBigInteger *)n
                                           withJavaMathBigInteger:(JavaMathBigInteger *)h
                                                    withByteArray:(IOSByteArray *)seed;

- (jboolean)isEqual:(id)o;

- (LibOrgBouncycastleMathEcECCurve *)getCurve;

- (LibOrgBouncycastleMathEcECPoint *)getG;

- (JavaMathBigInteger *)getH;

- (JavaMathBigInteger *)getN;

- (IOSByteArray *)getSeed;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecECParameterSpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecECParameterSpec *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *new_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *create_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecECParameterSpec *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *new_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *create_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(LibOrgBouncycastleJceSpecECParameterSpec *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *new_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECParameterSpec *create_LibOrgBouncycastleJceSpecECParameterSpec_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecECParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECParameterSpec_H