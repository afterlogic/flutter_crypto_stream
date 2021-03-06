//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecP128R1Curve.java
//

#ifndef SecP128R1Curve_H
#define SecP128R1Curve_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECCurve.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcCustomSecSecP128R1Point;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleMathEcECLookupTable;

@interface LibOrgBouncycastleMathEcCustomSecSecP128R1Curve : LibOrgBouncycastleMathEcECCurve_AbstractFp {
 @public
  LibOrgBouncycastleMathEcCustomSecSecP128R1Point *infinity_;
}
@property (readonly, class) JavaMathBigInteger *q NS_SWIFT_NAME(q);

+ (JavaMathBigInteger *)q;

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (JavaMathBigInteger *)getQ;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

#pragma mark Protected

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecP128R1Curve)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcCustomSecSecP128R1Curve, infinity_, LibOrgBouncycastleMathEcCustomSecSecP128R1Point *)

inline JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP128R1Curve_get_q(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathEcCustomSecSecP128R1Curve_q;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomSecSecP128R1Curve, q, JavaMathBigInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecP128R1Curve_init(LibOrgBouncycastleMathEcCustomSecSecP128R1Curve *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1Curve *new_LibOrgBouncycastleMathEcCustomSecSecP128R1Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecP128R1Curve *create_LibOrgBouncycastleMathEcCustomSecSecP128R1Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecP128R1Curve)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecP128R1Curve_H
