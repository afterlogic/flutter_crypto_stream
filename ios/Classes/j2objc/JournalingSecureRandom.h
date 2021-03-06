//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/JournalingSecureRandom.java
//

#ifndef JournalingSecureRandom_H
#define JournalingSecureRandom_H

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

@interface LibOrgBouncycastleCryptoUtilJournalingSecureRandom : JavaSecuritySecureRandom

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)transcript
               withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)clear;

- (IOSByteArray *)getTranscript;

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaSecuritySecureRandomSpi:(JavaSecuritySecureRandomSpi *)arg0
                                     withJavaSecurityProvider:(JavaSecurityProvider *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoUtilJournalingSecureRandom)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *self, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilJournalingSecureRandom *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilJournalingSecureRandom *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *self, IOSByteArray *transcript, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilJournalingSecureRandom *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(IOSByteArray *transcript, JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilJournalingSecureRandom *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(IOSByteArray *transcript, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoUtilJournalingSecureRandom)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JournalingSecureRandom_H
