//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ECCurve.java
//

#ifndef ECCurve_H
#define ECCurve_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve_Config;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@class LibOrgBouncycastleMathEcECPoint_Fp;
@protocol LibOrgBouncycastleMathEcECLookupTable;
@protocol LibOrgBouncycastleMathEcECMultiplier;
@protocol LibOrgBouncycastleMathEcEndoECEndomorphism;
@protocol LibOrgBouncycastleMathEcPreCompCallback;
@protocol LibOrgBouncycastleMathEcPreCompInfo;
@protocol LibOrgBouncycastleMathFieldFiniteField;

@interface LibOrgBouncycastleMathEcECCurve : NSObject {
 @public
  id<LibOrgBouncycastleMathFieldFiniteField> field_;
  LibOrgBouncycastleMathEcECFieldElement *a_;
  LibOrgBouncycastleMathEcECFieldElement *b_;
  JavaMathBigInteger *order_;
  JavaMathBigInteger *cofactor_;
  jint coord_;
  id<LibOrgBouncycastleMathEcEndoECEndomorphism> endomorphism_;
  id<LibOrgBouncycastleMathEcECMultiplier> multiplier_;
}
@property (readonly, class) jint COORD_AFFINE NS_SWIFT_NAME(COORD_AFFINE);
@property (readonly, class) jint COORD_HOMOGENEOUS NS_SWIFT_NAME(COORD_HOMOGENEOUS);
@property (readonly, class) jint COORD_JACOBIAN NS_SWIFT_NAME(COORD_JACOBIAN);
@property (readonly, class) jint COORD_JACOBIAN_CHUDNOVSKY NS_SWIFT_NAME(COORD_JACOBIAN_CHUDNOVSKY);
@property (readonly, class) jint COORD_JACOBIAN_MODIFIED NS_SWIFT_NAME(COORD_JACOBIAN_MODIFIED);
@property (readonly, class) jint COORD_LAMBDA_AFFINE NS_SWIFT_NAME(COORD_LAMBDA_AFFINE);
@property (readonly, class) jint COORD_LAMBDA_PROJECTIVE NS_SWIFT_NAME(COORD_LAMBDA_PROJECTIVE);
@property (readonly, class) jint COORD_SKEWED NS_SWIFT_NAME(COORD_SKEWED);

+ (jint)COORD_AFFINE;

+ (jint)COORD_HOMOGENEOUS;

+ (jint)COORD_JACOBIAN;

+ (jint)COORD_JACOBIAN_CHUDNOVSKY;

+ (jint)COORD_JACOBIAN_MODIFIED;

+ (jint)COORD_LAMBDA_AFFINE;

+ (jint)COORD_LAMBDA_PROJECTIVE;

+ (jint)COORD_SKEWED;

#pragma mark Public

- (LibOrgBouncycastleMathEcECCurve_Config *)configure;

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len;

- (LibOrgBouncycastleMathEcECPoint *)createPointWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                                withJavaMathBigInteger:(JavaMathBigInteger *)y;

- (LibOrgBouncycastleMathEcECPoint *)createPointWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                                withJavaMathBigInteger:(JavaMathBigInteger *)y
                                                           withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)decodePointWithByteArray:(IOSByteArray *)encoded;

- (jboolean)equalsWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)other;

- (jboolean)isEqual:(id)obj;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (LibOrgBouncycastleMathEcECFieldElement *)getA;

+ (IOSIntArray *)getAllCoordinateSystems;

- (LibOrgBouncycastleMathEcECFieldElement *)getB;

- (JavaMathBigInteger *)getCofactor;

- (jint)getCoordinateSystem;

- (id<LibOrgBouncycastleMathEcEndoECEndomorphism>)getEndomorphism;

- (id<LibOrgBouncycastleMathFieldFiniteField>)getField;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (id<LibOrgBouncycastleMathEcECMultiplier>)getMultiplier;

- (JavaMathBigInteger *)getOrder;

- (id<LibOrgBouncycastleMathEcPreCompInfo>)getPreCompInfoWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point
                                                                                withNSString:(NSString *)name;

- (NSUInteger)hash;

- (LibOrgBouncycastleMathEcECPoint *)importPointWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

- (jboolean)isValidFieldElementWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (void)normalizeAllWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points;

- (void)normalizeAllWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                     withInt:(jint)off
                                                     withInt:(jint)len
                  withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)iso;

- (id<LibOrgBouncycastleMathEcPreCompInfo>)precomputeWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point
                                                                            withNSString:(NSString *)name
                                             withLibOrgBouncycastleMathEcPreCompCallback:(id<LibOrgBouncycastleMathEcPreCompCallback>)callback;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

- (LibOrgBouncycastleMathEcECPoint *)validatePointWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)y;

- (LibOrgBouncycastleMathEcECPoint *)validatePointWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)y
                                                             withBoolean:(jboolean)withCompression;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleMathFieldFiniteField:(id<LibOrgBouncycastleMathFieldFiniteField>)field;

- (void)checkPointWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point;

- (void)checkPointsWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points;

- (void)checkPointsWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                    withInt:(jint)off
                                                    withInt:(jint)len;

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve;

- (id<LibOrgBouncycastleMathEcECMultiplier>)createDefaultMultiplier;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)decompressPointWithInt:(jint)yTilde
                                     withJavaMathBigInteger:(JavaMathBigInteger *)X1;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, field_, id<LibOrgBouncycastleMathFieldFiniteField>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, a_, LibOrgBouncycastleMathEcECFieldElement *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, b_, LibOrgBouncycastleMathEcECFieldElement *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, order_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, cofactor_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, endomorphism_, id<LibOrgBouncycastleMathEcEndoECEndomorphism>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve, multiplier_, id<LibOrgBouncycastleMathEcECMultiplier>)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_AFFINE(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_AFFINE 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_AFFINE, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_HOMOGENEOUS(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_HOMOGENEOUS 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_HOMOGENEOUS, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_JACOBIAN(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_JACOBIAN 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_JACOBIAN, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_JACOBIAN_CHUDNOVSKY(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_JACOBIAN_CHUDNOVSKY 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_JACOBIAN_CHUDNOVSKY, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_JACOBIAN_MODIFIED(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_JACOBIAN_MODIFIED 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_JACOBIAN_MODIFIED, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_LAMBDA_AFFINE(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_LAMBDA_AFFINE 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_LAMBDA_AFFINE, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_LAMBDA_PROJECTIVE(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_LAMBDA_PROJECTIVE 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_LAMBDA_PROJECTIVE, jint)

inline jint LibOrgBouncycastleMathEcECCurve_get_COORD_SKEWED(void);
#define LibOrgBouncycastleMathEcECCurve_COORD_SKEWED 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcECCurve, COORD_SKEWED, jint)

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcECCurve_getAllCoordinateSystems(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_initWithLibOrgBouncycastleMathFieldFiniteField_(LibOrgBouncycastleMathEcECCurve *self, id<LibOrgBouncycastleMathFieldFiniteField> field);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve)

@interface LibOrgBouncycastleMathEcECCurve_Config : NSObject {
 @public
  jint coord_;
  id<LibOrgBouncycastleMathEcEndoECEndomorphism> endomorphism_;
  id<LibOrgBouncycastleMathEcECMultiplier> multiplier_;
}

#pragma mark Public

- (LibOrgBouncycastleMathEcECCurve *)create;

- (LibOrgBouncycastleMathEcECCurve_Config *)setCoordinateSystemWithInt:(jint)coord;

- (LibOrgBouncycastleMathEcECCurve_Config *)setEndomorphismWithLibOrgBouncycastleMathEcEndoECEndomorphism:(id<LibOrgBouncycastleMathEcEndoECEndomorphism>)endomorphism;

- (LibOrgBouncycastleMathEcECCurve_Config *)setMultiplierWithLibOrgBouncycastleMathEcECMultiplier:(id<LibOrgBouncycastleMathEcECMultiplier>)multiplier;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)outer$
                                                          withInt:(jint)coord
                   withLibOrgBouncycastleMathEcEndoECEndomorphism:(id<LibOrgBouncycastleMathEcEndoECEndomorphism>)endomorphism
                         withLibOrgBouncycastleMathEcECMultiplier:(id<LibOrgBouncycastleMathEcECMultiplier>)multiplier;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve_Config)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve_Config, endomorphism_, id<LibOrgBouncycastleMathEcEndoECEndomorphism>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve_Config, multiplier_, id<LibOrgBouncycastleMathEcECMultiplier>)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_Config_initWithLibOrgBouncycastleMathEcECCurve_withInt_withLibOrgBouncycastleMathEcEndoECEndomorphism_withLibOrgBouncycastleMathEcECMultiplier_(LibOrgBouncycastleMathEcECCurve_Config *self, LibOrgBouncycastleMathEcECCurve *outer$, jint coord, id<LibOrgBouncycastleMathEcEndoECEndomorphism> endomorphism, id<LibOrgBouncycastleMathEcECMultiplier> multiplier);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Config *new_LibOrgBouncycastleMathEcECCurve_Config_initWithLibOrgBouncycastleMathEcECCurve_withInt_withLibOrgBouncycastleMathEcEndoECEndomorphism_withLibOrgBouncycastleMathEcECMultiplier_(LibOrgBouncycastleMathEcECCurve *outer$, jint coord, id<LibOrgBouncycastleMathEcEndoECEndomorphism> endomorphism, id<LibOrgBouncycastleMathEcECMultiplier> multiplier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Config *create_LibOrgBouncycastleMathEcECCurve_Config_initWithLibOrgBouncycastleMathEcECCurve_withInt_withLibOrgBouncycastleMathEcEndoECEndomorphism_withLibOrgBouncycastleMathEcECMultiplier_(LibOrgBouncycastleMathEcECCurve *outer$, jint coord, id<LibOrgBouncycastleMathEcEndoECEndomorphism> endomorphism, id<LibOrgBouncycastleMathEcECMultiplier> multiplier);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve_Config)

@interface LibOrgBouncycastleMathEcECCurve_AbstractFp : LibOrgBouncycastleMathEcECCurve

#pragma mark Public

- (jboolean)isValidFieldElementWithJavaMathBigInteger:(JavaMathBigInteger *)x;

#pragma mark Protected

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q;

- (LibOrgBouncycastleMathEcECPoint *)decompressPointWithInt:(jint)yTilde
                                     withJavaMathBigInteger:(JavaMathBigInteger *)X1;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve_AbstractFp)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_AbstractFp_initWithJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_AbstractFp *self, JavaMathBigInteger *q);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve_AbstractFp)

@interface LibOrgBouncycastleMathEcECCurve_Fp : LibOrgBouncycastleMathEcECCurve_AbstractFp {
 @public
  JavaMathBigInteger *q_;
  JavaMathBigInteger *r_;
  LibOrgBouncycastleMathEcECPoint_Fp *infinity_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a
                              withJavaMathBigInteger:(JavaMathBigInteger *)b;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)a
                              withJavaMathBigInteger:(JavaMathBigInteger *)b
                              withJavaMathBigInteger:(JavaMathBigInteger *)order
                              withJavaMathBigInteger:(JavaMathBigInteger *)cofactor;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (JavaMathBigInteger *)getQ;

- (LibOrgBouncycastleMathEcECPoint *)importPointWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

#pragma mark Protected

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)r
          withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)a
          withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)q
                              withJavaMathBigInteger:(JavaMathBigInteger *)r
          withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)a
          withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
                              withJavaMathBigInteger:(JavaMathBigInteger *)order
                              withJavaMathBigInteger:(JavaMathBigInteger *)cofactor;

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve_Fp)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve_Fp, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve_Fp, r_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcECCurve_Fp, infinity_, LibOrgBouncycastleMathEcECPoint_Fp *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *create_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *create_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECCurve_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *create_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_(JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_Fp *self, JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_Fp *create_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *q, JavaMathBigInteger *r, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve_Fp)

@interface LibOrgBouncycastleMathEcECCurve_AbstractF2m : LibOrgBouncycastleMathEcECCurve

#pragma mark Public

- (LibOrgBouncycastleMathEcECPoint *)createPointWithJavaMathBigInteger:(JavaMathBigInteger *)x
                                                withJavaMathBigInteger:(JavaMathBigInteger *)y
                                                           withBoolean:(jboolean)withCompression;

+ (JavaMathBigInteger *)inverseWithInt:(jint)m
                          withIntArray:(IOSIntArray *)ks
                withJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jboolean)isKoblitz;

- (jboolean)isValidFieldElementWithJavaMathBigInteger:(JavaMathBigInteger *)x;

#pragma mark Protected

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3;

- (LibOrgBouncycastleMathEcECPoint *)decompressPointWithInt:(jint)yTilde
                                     withJavaMathBigInteger:(JavaMathBigInteger *)X1;

- (LibOrgBouncycastleMathEcECFieldElement *)solveQuadraticEquationWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)beta;

#pragma mark Package-Private

- (IOSObjectArray *)getSi;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve_AbstractF2m)

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathEcECCurve_AbstractF2m_inverseWithInt_withIntArray_withJavaMathBigInteger_(jint m, IOSIntArray *ks, JavaMathBigInteger *x);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_AbstractF2m_initWithInt_withInt_withInt_withInt_(LibOrgBouncycastleMathEcECCurve_AbstractF2m *self, jint m, jint k1, jint k2, jint k3);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve_AbstractF2m)

@interface LibOrgBouncycastleMathEcECCurve_F2m : LibOrgBouncycastleMathEcECCurve_AbstractF2m

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k
               withJavaMathBigInteger:(JavaMathBigInteger *)a
               withJavaMathBigInteger:(JavaMathBigInteger *)b;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k
               withJavaMathBigInteger:(JavaMathBigInteger *)a
               withJavaMathBigInteger:(JavaMathBigInteger *)b
               withJavaMathBigInteger:(JavaMathBigInteger *)order
               withJavaMathBigInteger:(JavaMathBigInteger *)cofactor;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3
               withJavaMathBigInteger:(JavaMathBigInteger *)a
               withJavaMathBigInteger:(JavaMathBigInteger *)b;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3
               withJavaMathBigInteger:(JavaMathBigInteger *)a
               withJavaMathBigInteger:(JavaMathBigInteger *)b
               withJavaMathBigInteger:(JavaMathBigInteger *)order
               withJavaMathBigInteger:(JavaMathBigInteger *)cofactor;

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (jboolean)isTrinomial;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

#pragma mark Protected

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3
withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)a
withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)b
               withJavaMathBigInteger:(JavaMathBigInteger *)order
               withJavaMathBigInteger:(JavaMathBigInteger *)cofactor;

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve;

- (id<LibOrgBouncycastleMathEcECMultiplier>)createDefaultMultiplier;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                              withInt:(jint)arg1
                              withInt:(jint)arg2
                              withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECCurve_F2m)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_F2m *self, jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *create_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_F2m *self, jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *create_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_F2m *self, jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *create_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_F2m *self, jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *create_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleMathEcECCurve_F2m *self, jint m, jint k1, jint k2, jint k3, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECCurve_F2m *create_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withLibOrgBouncycastleMathEcECFieldElement_withLibOrgBouncycastleMathEcECFieldElement_withJavaMathBigInteger_withJavaMathBigInteger_(jint m, jint k1, jint k2, jint k3, LibOrgBouncycastleMathEcECFieldElement *a, LibOrgBouncycastleMathEcECFieldElement *b, JavaMathBigInteger *order, JavaMathBigInteger *cofactor);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECCurve_F2m)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECCurve_H
