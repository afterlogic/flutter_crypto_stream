//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/spec/McElieceCCA2KeyGenParameterSpec.java
//

#ifndef McElieceCCA2KeyGenParameterSpec_H
#define McElieceCCA2KeyGenParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >
@property (readonly, copy, class) NSString *SHA1 NS_SWIFT_NAME(SHA1);
@property (readonly, copy, class) NSString *SHA224 NS_SWIFT_NAME(SHA224);
@property (readonly, copy, class) NSString *SHA256 NS_SWIFT_NAME(SHA256);
@property (readonly, copy, class) NSString *SHA384 NS_SWIFT_NAME(SHA384);
@property (readonly, copy, class) NSString *SHA512 NS_SWIFT_NAME(SHA512);
@property (readonly, class) jint DEFAULT_M NS_SWIFT_NAME(DEFAULT_M);
@property (readonly, class) jint DEFAULT_T NS_SWIFT_NAME(DEFAULT_T);

+ (NSString *)SHA1;

+ (NSString *)SHA224;

+ (NSString *)SHA256;

+ (NSString *)SHA384;

+ (NSString *)SHA512;

+ (jint)DEFAULT_M;

+ (jint)DEFAULT_T;

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)keysize;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)t;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)t
                              withInt:(jint)poly;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)t
                              withInt:(jint)poly
                         withNSString:(NSString *)digest;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)t
                         withNSString:(NSString *)digest;

- (instancetype __nonnull)initWithInt:(jint)keysize
                         withNSString:(NSString *)digest;

- (NSString *)getDigest;

- (jint)getFieldPoly;

- (jint)getM;

- (jint)getN;

- (jint)getT;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec)

inline NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_SHA1(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_SHA1;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, SHA1, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_SHA224(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_SHA224;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, SHA224, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_SHA256(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_SHA256;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, SHA256, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_SHA384(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_SHA384;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, SHA384, NSString *)

inline NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_SHA512(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_SHA512;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, SHA512, NSString *)

inline jint LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_DEFAULT_M(void);
#define LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_DEFAULT_M 11
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, DEFAULT_M, jint)

inline jint LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_get_DEFAULT_T(void);
#define LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_DEFAULT_T 50
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec, DEFAULT_T, jint)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_init(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint keysize);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_(jint keysize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_(jint keysize);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withNSString_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint keysize, NSString *digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withNSString_(jint keysize, NSString *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withNSString_(jint keysize, NSString *digest);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint m, jint t);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_(jint m, jint t) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_(jint m, jint t);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withNSString_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint m, jint t, NSString *digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withNSString_(jint m, jint t, NSString *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withNSString_(jint m, jint t, NSString *digest);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint m, jint t, jint poly);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_(jint m, jint t, jint poly) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_(jint m, jint t, jint poly);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_withNSString_(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *self, jint m, jint t, jint poly, NSString *digest);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *new_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_withNSString_(jint m, jint t, jint poly, NSString *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec *create_LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec_initWithInt_withInt_withInt_withNSString_(jint m, jint t, jint poly, NSString *digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceSpecMcElieceCCA2KeyGenParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McElieceCCA2KeyGenParameterSpec_H