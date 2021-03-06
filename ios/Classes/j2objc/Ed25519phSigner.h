//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/Ed25519phSigner.java
//

#ifndef Ed25519phSigner_H
#define Ed25519phSigner_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoSignersEd25519phSigner : NSObject < LibOrgBouncycastleCryptoSigner >

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)context;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off
                    withInt:(jint)len;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersEd25519phSigner)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersEd25519phSigner_initWithByteArray_(LibOrgBouncycastleCryptoSignersEd25519phSigner *self, IOSByteArray *context);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd25519phSigner *new_LibOrgBouncycastleCryptoSignersEd25519phSigner_initWithByteArray_(IOSByteArray *context) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersEd25519phSigner *create_LibOrgBouncycastleCryptoSignersEd25519phSigner_initWithByteArray_(IOSByteArray *context);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersEd25519phSigner)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Ed25519phSigner_H
