//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PGPDigestCalculator.java
//

#ifndef PGPDigestCalculator_H
#define PGPDigestCalculator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoOutputStream;

@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator < JavaObject >

- (jint)getAlgorithm;

- (JavaIoOutputStream *)getOutputStream;

- (IOSByteArray *)getDigest;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPDigestCalculator_H
