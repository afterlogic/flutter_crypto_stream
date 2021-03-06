//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT193R1Point.java
//

#ifndef SecT193R1Point_H
#define SecT193R1Point_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECPoint.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECFieldElement;

@interface LibOrgBouncycastleMathEcCustomSecSecT193R1Point : LibOrgBouncycastleMathEcECPoint_AbstractF2m

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y;

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                      withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)addWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)b;

- (LibOrgBouncycastleMathEcECFieldElement *)getYCoord;

- (LibOrgBouncycastleMathEcECPoint *)negate;

- (LibOrgBouncycastleMathEcECPoint *)twice;

- (LibOrgBouncycastleMathEcECPoint *)twicePlusWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)b;

#pragma mark Protected

- (LibOrgBouncycastleMathEcECPoint *)detach;

- (jboolean)getCompressionYTilde;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                  withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                      withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)arg0
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)arg1
                       withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)arg2
                  withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT193R1Point)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcCustomSecSecT193R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcCustomSecSecT193R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcCustomSecSecT193R1Point *self, LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *new_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R1Point *create_LibOrgBouncycastleMathEcCustomSecSecT193R1Point_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElementArray_withBoolean_(LibOrgBouncycastleMathEcECCurve *curve, LibOrgBouncycastleMathEcECFieldElement *x, LibOrgBouncycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecT193R1Point)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecT193R1Point_H
