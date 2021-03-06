//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AbstractTlsSigner.java
//

#ifndef AbstractTlsSigner_H
#define AbstractTlsSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsSigner.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol LibOrgBouncycastleCryptoSigner;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@interface LibOrgBouncycastleCryptoTlsAbstractTlsSigner : NSObject < LibOrgBouncycastleCryptoTlsTlsSigner > {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsContext> context_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleCryptoSigner>)createSignerWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey;

- (id<LibOrgBouncycastleCryptoSigner>)createVerifyerWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

- (IOSByteArray *)generateRawSignatureWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                                 withByteArray:(IOSByteArray *)md5AndSha1;

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context OBJC_METHOD_FAMILY_NONE;

- (jboolean)verifyRawSignatureWithByteArray:(IOSByteArray *)sigBytes
withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                              withByteArray:(IOSByteArray *)md5AndSha1;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsAbstractTlsSigner)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsSigner, context_, id<LibOrgBouncycastleCryptoTlsTlsContext>)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAbstractTlsSigner_init(LibOrgBouncycastleCryptoTlsAbstractTlsSigner *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsAbstractTlsSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AbstractTlsSigner_H
