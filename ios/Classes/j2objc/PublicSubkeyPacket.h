//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/PublicSubkeyPacket.java
//

#ifndef PublicSubkeyPacket_H
#define PublicSubkeyPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PublicKeyPacket.h"

@class JavaUtilDate;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@protocol LibOrgBouncycastleBcpgBCPGKey;

@interface LibOrgBouncycastleBcpgPublicSubkeyPacket : LibOrgBouncycastleBcpgPublicKeyPacket

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)algorithm
                     withJavaUtilDate:(JavaUtilDate *)time
    withLibOrgBouncycastleBcpgBCPGKey:(id<LibOrgBouncycastleBcpgBCPGKey>)key;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgPublicSubkeyPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgPublicSubkeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicSubkeyPacket *new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicSubkeyPacket *create_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(LibOrgBouncycastleBcpgPublicSubkeyPacket *self, jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicSubkeyPacket *new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicSubkeyPacket *create_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgPublicSubkeyPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PublicSubkeyPacket_H
