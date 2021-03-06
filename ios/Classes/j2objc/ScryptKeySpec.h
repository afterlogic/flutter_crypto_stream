//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/ScryptKeySpec.java
//

#ifndef ScryptKeySpec_H
#define ScryptKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/KeySpec.h"

@class IOSByteArray;
@class IOSCharArray;

@interface LibOrgBouncycastleJcajceSpecScryptKeySpec : NSObject < JavaSecuritySpecKeySpec >

#pragma mark Public

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)password
                              withByteArray:(IOSByteArray *)salt
                                    withInt:(jint)costParameter
                                    withInt:(jint)blockSize
                                    withInt:(jint)parallelizationParameter
                                    withInt:(jint)keySize;

- (jint)getBlockSize;

- (jint)getCostParameter;

- (jint)getKeyLength;

- (jint)getParallelizationParameter;

- (IOSCharArray *)getPassword;

- (IOSByteArray *)getSalt;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceSpecScryptKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceSpecScryptKeySpec_initWithCharArray_withByteArray_withInt_withInt_withInt_withInt_(LibOrgBouncycastleJcajceSpecScryptKeySpec *self, IOSCharArray *password, IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keySize);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecScryptKeySpec *new_LibOrgBouncycastleJcajceSpecScryptKeySpec_initWithCharArray_withByteArray_withInt_withInt_withInt_withInt_(IOSCharArray *password, IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keySize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceSpecScryptKeySpec *create_LibOrgBouncycastleJcajceSpecScryptKeySpec_initWithCharArray_withByteArray_withInt_withInt_withInt_withInt_(IOSCharArray *password, IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keySize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceSpecScryptKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ScryptKeySpec_H
