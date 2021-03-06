//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/MQVPrivateKeySpec.java
//

#ifndef MQVPrivateKeySpec_H
#define MQVPrivateKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "MQVPrivateKey.h"
#include "java/security/spec/KeySpec.h"

@class IOSByteArray;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastleJceSpecMQVPrivateKeySpec : NSObject < JavaSecuritySpecKeySpec, LibOrgBouncycastleJceInterfacesMQVPrivateKey >

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)staticPrivateKey
                              withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)ephemeralPrivateKey;

- (instancetype __nonnull)initWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)staticPrivateKey
                              withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)ephemeralPrivateKey
                               withJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)ephemeralPublicKey;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (id<JavaSecurityPrivateKey>)getEphemeralPrivateKey;

- (id<JavaSecurityPublicKey>)getEphemeralPublicKey;

- (NSString *)getFormat;

- (id<JavaSecurityPrivateKey>)getStaticPrivateKey;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecMQVPrivateKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleJceSpecMQVPrivateKeySpec *self, id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecMQVPrivateKeySpec *new_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecMQVPrivateKeySpec *create_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(LibOrgBouncycastleJceSpecMQVPrivateKeySpec *self, id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecMQVPrivateKeySpec *new_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecMQVPrivateKeySpec *create_LibOrgBouncycastleJceSpecMQVPrivateKeySpec_initWithJavaSecurityPrivateKey_withJavaSecurityPrivateKey_withJavaSecurityPublicKey_(id<JavaSecurityPrivateKey> staticPrivateKey, id<JavaSecurityPrivateKey> ephemeralPrivateKey, id<JavaSecurityPublicKey> ephemeralPublicKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecMQVPrivateKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MQVPrivateKeySpec_H
