//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/PSKTlsServer.java
//

#ifndef PSKTlsServer_H
#define PSKTlsServer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractTlsServer.h"
#include "J2ObjC_header.h"

@class IOSIntArray;
@class LibOrgBouncycastleCryptoParamsDHParameters;
@protocol LibOrgBouncycastleCryptoTlsTlsCipherFactory;
@protocol LibOrgBouncycastleCryptoTlsTlsCredentials;
@protocol LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials;
@protocol LibOrgBouncycastleCryptoTlsTlsKeyExchange;
@protocol LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;

@interface LibOrgBouncycastleCryptoTlsPSKTlsServer : LibOrgBouncycastleCryptoTlsAbstractTlsServer {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)cipherFactory
                         withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager;

- (id<LibOrgBouncycastleCryptoTlsTlsCredentials>)getCredentials;

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)getKeyExchange;

#pragma mark Protected

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)createPSKKeyExchangeWithInt:(jint)keyExchange;

- (IOSIntArray *)getCipherSuites;

- (LibOrgBouncycastleCryptoParamsDHParameters *)getDHParameters;

- (id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>)getRSAEncryptionCredentials;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsPSKTlsServer)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsPSKTlsServer, pskIdentityManager_, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(LibOrgBouncycastleCryptoTlsPSKTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsPSKTlsServer *new_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsPSKTlsServer *create_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(LibOrgBouncycastleCryptoTlsPSKTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsPSKTlsServer *new_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsPSKTlsServer *create_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsPSKTlsServer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PSKTlsServer_H