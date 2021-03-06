//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/GLVMultiplier.java
//

#ifndef GLVMultiplier_H
#define GLVMultiplier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractECMultiplier.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleMathEcEndoGLVEndomorphism;

@interface LibOrgBouncycastleMathEcGLVMultiplier : LibOrgBouncycastleMathEcAbstractECMultiplier {
 @public
  LibOrgBouncycastleMathEcECCurve *curve_;
  id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                  withLibOrgBouncycastleMathEcEndoGLVEndomorphism:(id<LibOrgBouncycastleMathEcEndoGLVEndomorphism>)glvEndomorphism;

#pragma mark Protected

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcGLVMultiplier)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcGLVMultiplier, curve_, LibOrgBouncycastleMathEcECCurve *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcGLVMultiplier, glvEndomorphism_, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism>)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcGLVMultiplier *self, LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcGLVMultiplier *new_LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcGLVMultiplier *create_LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcGLVMultiplier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GLVMultiplier_H
