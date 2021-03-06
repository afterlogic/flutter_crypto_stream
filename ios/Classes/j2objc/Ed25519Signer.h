//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/Ed25519Signer.java
//

#ifndef Ed25519Signer_H
#define Ed25519Signer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoSignersEd25519Signer : NSObject < LibOrgBouncycastleCryptoSigner >

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off
                    withInt:(jint)len;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersEd25519Signer)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersEd25519Signer_init(LibOrgBouncycastleCryptoSignersEd25519Signer *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd25519Signer *new_LibOrgBouncycastleCryptoSignersEd25519Signer_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd25519Signer *create_LibOrgBouncycastleCryptoSignersEd25519Signer_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersEd25519Signer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Ed25519Signer_H
