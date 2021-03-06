//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DefaultTlsEncryptionCredentials.java
//

#ifndef DefaultTlsEncryptionCredentials_H
#define DefaultTlsEncryptionCredentials_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractTlsEncryptionCredentials.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastleCryptoTlsCertificate;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@interface LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials : LibOrgBouncycastleCryptoTlsAbstractTlsEncryptionCredentials {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsContext> context_;
  LibOrgBouncycastleCryptoTlsCertificate *certificate_;
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                             withLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate
               withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey;

- (IOSByteArray *)decryptPreMasterSecretWithByteArray:(IOSByteArray *)encryptedPreMasterSecret;

- (LibOrgBouncycastleCryptoTlsCertificate *)getCertificate;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials, context_, id<LibOrgBouncycastleCryptoTlsTlsContext>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials, certificate_, LibOrgBouncycastleCryptoTlsCertificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials, privateKey_, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *new_LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *create_LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DefaultTlsEncryptionCredentials_H
