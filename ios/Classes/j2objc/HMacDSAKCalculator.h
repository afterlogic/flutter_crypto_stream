//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/HMacDSAKCalculator.java
//

#ifndef HMacDSAKCalculator_H
#define HMacDSAKCalculator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "DSAKCalculator.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoSignersHMacDSAKCalculator : NSObject < LibOrgBouncycastleCryptoSignersDSAKCalculator >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)n
              withJavaMathBigInteger:(JavaMathBigInteger *)d
                       withByteArray:(IOSByteArray *)message OBJC_METHOD_FAMILY_NONE;

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)n
        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (jboolean)isDeterministic;

- (JavaMathBigInteger *)nextK;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoSignersHMacDSAKCalculator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersHMacDSAKCalculator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersHMacDSAKCalculator *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersHMacDSAKCalculator *new_LibOrgBouncycastleCryptoSignersHMacDSAKCalculator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersHMacDSAKCalculator *create_LibOrgBouncycastleCryptoSignersHMacDSAKCalculator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersHMacDSAKCalculator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HMacDSAKCalculator_H
