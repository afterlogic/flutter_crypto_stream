//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/X931SecureRandom.java
//

#ifndef X931SecureRandom_H
#define X931SecureRandom_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/SecureRandom.h"

@class IOSByteArray;
@class JavaSecurityProvider;
@class JavaSecuritySecureRandomSpi;
@class LibOrgBouncycastleCryptoPrngX931RNG;

@interface LibOrgBouncycastleCryptoPrngX931SecureRandom : JavaSecuritySecureRandom

#pragma mark Public

- (IOSByteArray *)generateSeedWithInt:(jint)numBytes;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

- (void)setSeedWithByteArray:(IOSByteArray *)seed;

- (void)setSeedWithLong:(jlong)seed;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)randomSource
                   withLibOrgBouncycastleCryptoPrngX931RNG:(LibOrgBouncycastleCryptoPrngX931RNG *)drbg
                                               withBoolean:(jboolean)predictionResistant;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaSecuritySecureRandomSpi:(JavaSecuritySecureRandomSpi *)arg0
                                     withJavaSecurityProvider:(JavaSecurityProvider *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoPrngX931SecureRandom)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngX931RNG_withBoolean_(LibOrgBouncycastleCryptoPrngX931SecureRandom *self, JavaSecuritySecureRandom *randomSource, LibOrgBouncycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngX931SecureRandom *new_LibOrgBouncycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngX931RNG_withBoolean_(JavaSecuritySecureRandom *randomSource, LibOrgBouncycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPrngX931SecureRandom *create_LibOrgBouncycastleCryptoPrngX931SecureRandom_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoPrngX931RNG_withBoolean_(JavaSecuritySecureRandom *randomSource, LibOrgBouncycastleCryptoPrngX931RNG *drbg, jboolean predictionResistant);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPrngX931SecureRandom)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X931SecureRandom_H
