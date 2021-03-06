//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ServerOnlyTlsAuthentication.java
//

#ifndef ServerOnlyTlsAuthentication_H
#define ServerOnlyTlsAuthentication_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsAuthentication.h"

@class LibOrgBouncycastleCryptoTlsCertificateRequest;
@protocol LibOrgBouncycastleCryptoTlsTlsCredentials;

@interface LibOrgBouncycastleCryptoTlsServerOnlyTlsAuthentication : NSObject < LibOrgBouncycastleCryptoTlsTlsAuthentication >

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleCryptoTlsTlsCredentials>)getClientCredentialsWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsServerOnlyTlsAuthentication)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsServerOnlyTlsAuthentication_init(LibOrgBouncycastleCryptoTlsServerOnlyTlsAuthentication *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsServerOnlyTlsAuthentication)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ServerOnlyTlsAuthentication_H
