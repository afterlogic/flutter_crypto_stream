//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsSigner.java
//

#ifndef TlsSigner_H
#define TlsSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@class LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;
@protocol LibOrgBouncycastleCryptoSigner;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@protocol LibOrgBouncycastleCryptoTlsTlsSigner < JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)generateRawSignatureWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                                 withByteArray:(IOSByteArray *)md5AndSha1;

- (IOSByteArray *)generateRawSignatureWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                      withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                                 withByteArray:(IOSByteArray *)hash_;

- (jboolean)verifyRawSignatureWithByteArray:(IOSByteArray *)sigBytes
withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                              withByteArray:(IOSByteArray *)md5AndSha1;

- (jboolean)verifyRawSignatureWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                                         withByteArray:(IOSByteArray *)sigBytes
                              withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                                                                         withByteArray:(IOSByteArray *)hash_;

- (id<LibOrgBouncycastleCryptoSigner>)createSignerWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey;

- (id<LibOrgBouncycastleCryptoSigner>)createSignerWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                  withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey;

- (id<LibOrgBouncycastleCryptoSigner>)createVerifyerWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

- (id<LibOrgBouncycastleCryptoSigner>)createVerifyerWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                    withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

- (jboolean)isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsSigner)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsSigner_H
