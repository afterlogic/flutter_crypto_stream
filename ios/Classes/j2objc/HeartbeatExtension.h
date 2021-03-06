//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/HeartbeatExtension.java
//

#ifndef HeartbeatExtension_H
#define HeartbeatExtension_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoInputStream;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleCryptoTlsHeartbeatExtension : NSObject {
 @public
  jshort mode_;
}

#pragma mark Public

- (instancetype __nonnull)initWithShort:(jshort)mode;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (jshort)getMode;

+ (LibOrgBouncycastleCryptoTlsHeartbeatExtension *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsHeartbeatExtension)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsHeartbeatExtension_initWithShort_(LibOrgBouncycastleCryptoTlsHeartbeatExtension *self, jshort mode);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsHeartbeatExtension *new_LibOrgBouncycastleCryptoTlsHeartbeatExtension_initWithShort_(jshort mode) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsHeartbeatExtension *create_LibOrgBouncycastleCryptoTlsHeartbeatExtension_initWithShort_(jshort mode);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsHeartbeatExtension *LibOrgBouncycastleCryptoTlsHeartbeatExtension_parseWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsHeartbeatExtension)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HeartbeatExtension_H
