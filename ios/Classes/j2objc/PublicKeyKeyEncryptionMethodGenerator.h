//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PublicKeyKeyEncryptionMethodGenerator.java
//

#ifndef PublicKeyKeyEncryptionMethodGenerator_H
#define PublicKeyKeyEncryptionMethodGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPKeyEncryptionMethodGenerator.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleBcpgContainedPacket;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;

@interface LibOrgBouncycastleOpenpgpOperatorPublicKeyKeyEncryptionMethodGenerator : LibOrgBouncycastleOpenpgpOperatorPGPKeyEncryptionMethodGenerator

#pragma mark Public

- (LibOrgBouncycastleBcpgContainedPacket *)generateWithInt:(jint)encAlgorithm
                                             withByteArray:(IOSByteArray *)sessionInfo;

- (IOSObjectArray *)processSessionInfoWithByteArray:(IOSByteArray *)encryptedSessionInfo;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (IOSByteArray *)encryptSessionInfoWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                                                                withByteArray:(IOSByteArray *)sessionInfo;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorPublicKeyKeyEncryptionMethodGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorPublicKeyKeyEncryptionMethodGenerator_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpOperatorPublicKeyKeyEncryptionMethodGenerator *self, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorPublicKeyKeyEncryptionMethodGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PublicKeyKeyEncryptionMethodGenerator_H
