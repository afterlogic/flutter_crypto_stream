//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/HeartbeatMessageType.java
//

#ifndef HeartbeatMessageType_H
#define HeartbeatMessageType_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsHeartbeatMessageType : NSObject
@property (readonly, class) jshort heartbeat_request NS_SWIFT_NAME(heartbeat_request);
@property (readonly, class) jshort heartbeat_response NS_SWIFT_NAME(heartbeat_response);

+ (jshort)heartbeat_request;

+ (jshort)heartbeat_response;

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)isValidWithShort:(jshort)heartbeatMessageType;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsHeartbeatMessageType)

inline jshort LibOrgBouncycastleCryptoTlsHeartbeatMessageType_get_heartbeat_request(void);
#define LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_request 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsHeartbeatMessageType, heartbeat_request, jshort)

inline jshort LibOrgBouncycastleCryptoTlsHeartbeatMessageType_get_heartbeat_response(void);
#define LibOrgBouncycastleCryptoTlsHeartbeatMessageType_heartbeat_response 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsHeartbeatMessageType, heartbeat_response, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init(LibOrgBouncycastleCryptoTlsHeartbeatMessageType *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsHeartbeatMessageType *new_LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsHeartbeatMessageType *create_LibOrgBouncycastleCryptoTlsHeartbeatMessageType_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoTlsHeartbeatMessageType_isValidWithShort_(jshort heartbeatMessageType);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsHeartbeatMessageType)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HeartbeatMessageType_H