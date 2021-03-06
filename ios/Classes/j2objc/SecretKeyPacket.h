//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SecretKeyPacket.java
//

#ifndef SecretKeyPacket_H
#define SecretKeyPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ContainedPacket.h"
#include "J2ObjC_header.h"
#include "PublicKeyAlgorithmTags.h"

@class IOSByteArray;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@class LibOrgBouncycastleBcpgPublicKeyPacket;
@class LibOrgBouncycastleBcpgS2K;

@interface LibOrgBouncycastleBcpgSecretKeyPacket : LibOrgBouncycastleBcpgContainedPacket < LibOrgBouncycastleBcpgPublicKeyAlgorithmTags >
@property (readonly, class) jint USAGE_NONE NS_SWIFT_NAME(USAGE_NONE);
@property (readonly, class) jint USAGE_CHECKSUM NS_SWIFT_NAME(USAGE_CHECKSUM);
@property (readonly, class) jint USAGE_SHA1 NS_SWIFT_NAME(USAGE_SHA1);

+ (jint)USAGE_NONE;

+ (jint)USAGE_CHECKSUM;

+ (jint)USAGE_SHA1;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                                withInt:(jint)encAlgorithm
                                                                withInt:(jint)s2kUsage
                                          withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                          withByteArray:(IOSByteArray *)iv
                                                          withByteArray:(IOSByteArray *)secKeyData;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                                withInt:(jint)encAlgorithm
                                          withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                          withByteArray:(IOSByteArray *)iv
                                                          withByteArray:(IOSByteArray *)secKeyData;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (jint)getEncAlgorithm;

- (IOSByteArray *)getEncodedContents;

- (IOSByteArray *)getIV;

- (LibOrgBouncycastleBcpgPublicKeyPacket *)getPublicKeyPacket;

- (LibOrgBouncycastleBcpgS2K *)getS2K;

- (jint)getS2KUsage;

- (IOSByteArray *)getSecretKeyData;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSecretKeyPacket)

inline jint LibOrgBouncycastleBcpgSecretKeyPacket_get_USAGE_NONE(void);
#define LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_NONE 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSecretKeyPacket, USAGE_NONE, jint)

inline jint LibOrgBouncycastleBcpgSecretKeyPacket_get_USAGE_CHECKSUM(void);
#define LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_CHECKSUM 255
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSecretKeyPacket, USAGE_CHECKSUM, jint)

inline jint LibOrgBouncycastleBcpgSecretKeyPacket_get_USAGE_SHA1(void);
#define LibOrgBouncycastleBcpgSecretKeyPacket_USAGE_SHA1 254
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSecretKeyPacket, USAGE_SHA1, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretKeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *new_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretKeyPacket *create_LibOrgBouncycastleBcpgSecretKeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSecretKeyPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecretKeyPacket_H
