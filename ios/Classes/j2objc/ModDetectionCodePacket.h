//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ModDetectionCodePacket.java
//

#ifndef ModDetectionCodePacket_H
#define ModDetectionCodePacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ContainedPacket.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;

@interface LibOrgBouncycastleBcpgModDetectionCodePacket : LibOrgBouncycastleBcpgContainedPacket

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)digest;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (IOSByteArray *)getDigest;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgModDetectionCodePacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgModDetectionCodePacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgModDetectionCodePacket *new_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgModDetectionCodePacket *create_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(LibOrgBouncycastleBcpgModDetectionCodePacket *self, IOSByteArray *digest);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgModDetectionCodePacket *new_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(IOSByteArray *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgModDetectionCodePacket *create_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(IOSByteArray *digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgModDetectionCodePacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ModDetectionCodePacket_H