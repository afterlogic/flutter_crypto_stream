//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PGPDigestCalculatorProvider.java
//

#ifndef PGPDigestCalculatorProvider_H
#define PGPDigestCalculatorProvider_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;

@protocol LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider < JavaObject >

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getWithInt:(jint)algorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPDigestCalculatorProvider_H