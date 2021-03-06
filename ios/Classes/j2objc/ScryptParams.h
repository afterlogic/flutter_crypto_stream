//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/misc/ScryptParams.java
//

#ifndef ScryptParams_H
#define ScryptParams_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1MiscScryptParams : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)salt
                     withJavaMathBigInteger:(JavaMathBigInteger *)costParameter
                     withJavaMathBigInteger:(JavaMathBigInteger *)blockSize
                     withJavaMathBigInteger:(JavaMathBigInteger *)parallelizationParameter
                     withJavaMathBigInteger:(JavaMathBigInteger *)keyLength;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)salt
                                    withInt:(jint)costParameter
                                    withInt:(jint)blockSize
                                    withInt:(jint)parallelizationParameter;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)salt
                                    withInt:(jint)costParameter
                                    withInt:(jint)blockSize
                                    withInt:(jint)parallelizationParameter
                                    withInt:(jint)keyLength;

- (JavaMathBigInteger *)getBlockSize;

- (JavaMathBigInteger *)getCostParameter;

+ (LibOrgBouncycastleAsn1MiscScryptParams *)getInstanceWithId:(id)o;

- (JavaMathBigInteger *)getKeyLength;

- (JavaMathBigInteger *)getParallelizationParameter;

- (IOSByteArray *)getSalt;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1MiscScryptParams)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_(LibOrgBouncycastleAsn1MiscScryptParams *self, IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *new_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_(IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *create_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_(IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_withInt_(LibOrgBouncycastleAsn1MiscScryptParams *self, IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keyLength);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *new_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_withInt_(IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keyLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *create_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withInt_withInt_withInt_withInt_(IOSByteArray *salt, jint costParameter, jint blockSize, jint parallelizationParameter, jint keyLength);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1MiscScryptParams *self, IOSByteArray *salt, JavaMathBigInteger *costParameter, JavaMathBigInteger *blockSize, JavaMathBigInteger *parallelizationParameter, JavaMathBigInteger *keyLength);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *new_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(IOSByteArray *salt, JavaMathBigInteger *costParameter, JavaMathBigInteger *blockSize, JavaMathBigInteger *parallelizationParameter, JavaMathBigInteger *keyLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *create_LibOrgBouncycastleAsn1MiscScryptParams_initWithByteArray_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(IOSByteArray *salt, JavaMathBigInteger *costParameter, JavaMathBigInteger *blockSize, JavaMathBigInteger *parallelizationParameter, JavaMathBigInteger *keyLength);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MiscScryptParams *LibOrgBouncycastleAsn1MiscScryptParams_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1MiscScryptParams)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ScryptParams_H
