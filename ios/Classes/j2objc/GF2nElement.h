//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/GF2nElement.java
//

#ifndef GF2nElement_H
#define GF2nElement_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GFElement.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastlePqcMathLinearalgebraGF2nField;

@interface LibOrgBouncycastlePqcMathLinearalgebraGF2nElement : NSObject < LibOrgBouncycastlePqcMathLinearalgebraGFElement > {
 @public
  LibOrgBouncycastlePqcMathLinearalgebraGF2nField *mField_;
  jint mDegree_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)convertWithLibOrgBouncycastlePqcMathLinearalgebraGF2nField:(LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)basis;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)getField;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)increase;

- (void)increaseThis;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)solveQuadraticEquation;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)square;

- (LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *)squareRoot;

- (void)squareRootThis;

- (void)squareThis;

- (id<LibOrgBouncycastlePqcMathLinearalgebraGFElement>)subtractWithLibOrgBouncycastlePqcMathLinearalgebraGFElement:(id<LibOrgBouncycastlePqcMathLinearalgebraGFElement>)minuend;

- (void)subtractFromThisWithLibOrgBouncycastlePqcMathLinearalgebraGFElement:(id<LibOrgBouncycastlePqcMathLinearalgebraGFElement>)minuend;

- (jboolean)testRightmostBit;

- (jint)trace;

#pragma mark Package-Private

- (void)assignOne;

- (void)assignZero;

- (jboolean)testBitWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraGF2nElement)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathLinearalgebraGF2nElement, mField_, LibOrgBouncycastlePqcMathLinearalgebraGF2nField *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraGF2nElement_init(LibOrgBouncycastlePqcMathLinearalgebraGF2nElement *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraGF2nElement)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GF2nElement_H
