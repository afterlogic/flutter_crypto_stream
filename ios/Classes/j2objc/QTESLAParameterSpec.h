//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/QTESLAParameterSpec.java
//

#ifndef QTESLAParameterSpec_H
#define QTESLAParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >
@property (readonly, copy, class) NSString *HEURISTIC_I NS_SWIFT_NAME(HEURISTIC_I);
@property (readonly, copy, class) NSString *HEURISTIC_III_SIZE NS_SWIFT_NAME(HEURISTIC_III_SIZE);
@property (readonly, copy, class) NSString *HEURISTIC_III_SPEED NS_SWIFT_NAME(HEURISTIC_III_SPEED);
@property (readonly, copy, class) NSString *PROVABLY_SECURE_I NS_SWIFT_NAME(PROVABLY_SECURE_I);
@property (readonly, copy, class) NSString *PROVABLY_SECURE_III NS_SWIFT_NAME(PROVABLY_SECURE_III);

+ (NSString *)HEURISTIC_I;

+ (NSString *)HEURISTIC_III_SIZE;

+ (NSString *)HEURISTIC_III_SPEED;

+ (NSString *)PROVABLY_SECURE_I;

+ (NSString *)PROVABLY_SECURE_III;

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)securityCategory;

- (NSString *)getSecurityCategory;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec)

inline NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_get_HEURISTIC_I(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_HEURISTIC_I;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec, HEURISTIC_I, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_get_HEURISTIC_III_SIZE(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_HEURISTIC_III_SIZE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec, HEURISTIC_III_SIZE, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_get_HEURISTIC_III_SPEED(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_HEURISTIC_III_SPEED;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec, HEURISTIC_III_SPEED, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_get_PROVABLY_SECURE_I(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_PROVABLY_SECURE_I;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec, PROVABLY_SECURE_I, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_get_PROVABLY_SECURE_III(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_PROVABLY_SECURE_III;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec, PROVABLY_SECURE_III, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_initWithNSString_(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec *self, NSString *securityCategory);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_initWithNSString_(NSString *securityCategory) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec_initWithNSString_(NSString *securityCategory);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceSpecQTESLAParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // QTESLAParameterSpec_H
