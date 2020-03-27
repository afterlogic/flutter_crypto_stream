//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ECAlgorithms.java
//

#ifndef ECAlgorithms_H
#define ECAlgorithms_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleMathEcECPointMap;
@protocol LibOrgBouncycastleMathEcEndoGLVEndomorphism;
@protocol LibOrgBouncycastleMathFieldFiniteField;

@interface LibOrgBouncycastleMathEcECAlgorithms : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleMathEcECPoint *)cleanPointWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c
                                               withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

+ (LibOrgBouncycastleMathEcECPoint *)importPointWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c
                                                withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

+ (jboolean)isF2mCurveWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c;

+ (jboolean)isF2mFieldWithLibOrgBouncycastleMathFieldFiniteField:(id<LibOrgBouncycastleMathFieldFiniteField>)field;

+ (jboolean)isFpCurveWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c;

+ (jboolean)isFpFieldWithLibOrgBouncycastleMathFieldFiniteField:(id<LibOrgBouncycastleMathFieldFiniteField>)field;

+ (void)montgomeryTrickWithLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                               withInt:(jint)off
                                                               withInt:(jint)len;

+ (void)montgomeryTrickWithLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                               withInt:(jint)off
                                                               withInt:(jint)len
                            withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)scale_;

+ (LibOrgBouncycastleMathEcECPoint *)referenceMultiplyWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                   withJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (LibOrgBouncycastleMathEcECPoint *)shamirsTrickWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)P
                                                              withJavaMathBigInteger:(JavaMathBigInteger *)k
                                                 withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)Q
                                                              withJavaMathBigInteger:(JavaMathBigInteger *)l;

+ (LibOrgBouncycastleMathEcECPoint *)sumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)ps
                                                                 withJavaMathBigIntegerArray:(IOSObjectArray *)ks;

+ (LibOrgBouncycastleMathEcECPoint *)sumOfTwoMultipliesWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)P
                                                                    withJavaMathBigInteger:(JavaMathBigInteger *)a
                                                       withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)Q
                                                                    withJavaMathBigInteger:(JavaMathBigInteger *)b;

+ (LibOrgBouncycastleMathEcECPoint *)validatePointWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

#pragma mark Package-Private

+ (LibOrgBouncycastleMathEcECPoint *)implCheckResultWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

+ (LibOrgBouncycastleMathEcECPoint *)implShamirsTrickJsfWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)P
                                                                     withJavaMathBigInteger:(JavaMathBigInteger *)k
                                                        withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)Q
                                                                     withJavaMathBigInteger:(JavaMathBigInteger *)l;

+ (LibOrgBouncycastleMathEcECPoint *)implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)P
                                                                      withJavaMathBigInteger:(JavaMathBigInteger *)k
                                                         withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)Q
                                                                      withJavaMathBigInteger:(JavaMathBigInteger *)l;

+ (LibOrgBouncycastleMathEcECPoint *)implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)P
                                                                      withJavaMathBigInteger:(JavaMathBigInteger *)k
                                                      withLibOrgBouncycastleMathEcECPointMap:(id<LibOrgBouncycastleMathEcECPointMap>)pointMapQ
                                                                      withJavaMathBigInteger:(JavaMathBigInteger *)l;

+ (LibOrgBouncycastleMathEcECPoint *)implSumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)ps
                                                                     withJavaMathBigIntegerArray:(IOSObjectArray *)ks;

+ (LibOrgBouncycastleMathEcECPoint *)implSumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)ps
                                                          withLibOrgBouncycastleMathEcECPointMap:(id<LibOrgBouncycastleMathEcECPointMap>)pointMap
                                                                     withJavaMathBigIntegerArray:(IOSObjectArray *)ks;

+ (LibOrgBouncycastleMathEcECPoint *)implSumOfMultipliesGLVWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)ps
                                                                        withJavaMathBigIntegerArray:(IOSObjectArray *)ks
                                                    withLibOrgBouncycastleMathEcEndoGLVEndomorphism:(id<LibOrgBouncycastleMathEcEndoGLVEndomorphism>)glvEndomorphism;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECAlgorithms)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECAlgorithms_init(LibOrgBouncycastleMathEcECAlgorithms *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECAlgorithms *new_LibOrgBouncycastleMathEcECAlgorithms_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECAlgorithms *create_LibOrgBouncycastleMathEcECAlgorithms_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathEcECAlgorithms_isF2mCurveWithLibOrgBouncycastleMathEcECCurve_(LibOrgBouncycastleMathEcECCurve *c);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathEcECAlgorithms_isF2mFieldWithLibOrgBouncycastleMathFieldFiniteField_(id<LibOrgBouncycastleMathFieldFiniteField> field);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathEcECAlgorithms_isFpCurveWithLibOrgBouncycastleMathEcECCurve_(LibOrgBouncycastleMathEcECCurve *c);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathEcECAlgorithms_isFpFieldWithLibOrgBouncycastleMathFieldFiniteField_(id<LibOrgBouncycastleMathFieldFiniteField> field);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_sumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray_withJavaMathBigIntegerArray_(IOSObjectArray *ps, IOSObjectArray *ks);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_sumOfTwoMultipliesWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *P, JavaMathBigInteger *a, LibOrgBouncycastleMathEcECPoint *Q, JavaMathBigInteger *b);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_shamirsTrickWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *P, JavaMathBigInteger *k, LibOrgBouncycastleMathEcECPoint *Q, JavaMathBigInteger *l);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_importPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECCurve *c, LibOrgBouncycastleMathEcECPoint *p);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECAlgorithms_montgomeryTrickWithLibOrgBouncycastleMathEcECFieldElementArray_withInt_withInt_(IOSObjectArray *zs, jint off, jint len);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECAlgorithms_montgomeryTrickWithLibOrgBouncycastleMathEcECFieldElementArray_withInt_withInt_withLibOrgBouncycastleMathEcECFieldElement_(IOSObjectArray *zs, jint off, jint len, LibOrgBouncycastleMathEcECFieldElement *scale_);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_referenceMultiplyWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *p, JavaMathBigInteger *k);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_validatePointWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *p);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECCurve *c, LibOrgBouncycastleMathEcECPoint *p);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implCheckResultWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *p);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implShamirsTrickJsfWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *P, JavaMathBigInteger *k, LibOrgBouncycastleMathEcECPoint *Q, JavaMathBigInteger *l);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *P, JavaMathBigInteger *k, LibOrgBouncycastleMathEcECPoint *Q, JavaMathBigInteger *l);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPointMap_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECPoint *P, JavaMathBigInteger *k, id<LibOrgBouncycastleMathEcECPointMap> pointMapQ, JavaMathBigInteger *l);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implSumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray_withJavaMathBigIntegerArray_(IOSObjectArray *ps, IOSObjectArray *ks);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implSumOfMultipliesGLVWithLibOrgBouncycastleMathEcECPointArray_withJavaMathBigIntegerArray_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(IOSObjectArray *ps, IOSObjectArray *ks, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcECAlgorithms_implSumOfMultipliesWithLibOrgBouncycastleMathEcECPointArray_withLibOrgBouncycastleMathEcECPointMap_withJavaMathBigIntegerArray_(IOSObjectArray *ps, id<LibOrgBouncycastleMathEcECPointMap> pointMap, IOSObjectArray *ks);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECAlgorithms)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECAlgorithms_H