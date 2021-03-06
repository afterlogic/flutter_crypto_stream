//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/encryption_signing/EncryptionBuilderInterface.java
//

#ifndef EncryptionBuilderInterface_H
#define EncryptionBuilderInterface_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaIoOutputStream;
@class LibComAfterlogicPgpAlgorithmCompressionAlgorithm;
@class LibComAfterlogicPgpAlgorithmHashAlgorithmUtil;
@class LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;
@class LibComAfterlogicPgpEncryption_signingEncryptionStream;
@class LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy;
@class LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy;
@class LibComAfterlogicPgpUtilMultiMap;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;
@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor;
@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith;
@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients;
@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms;
@protocol LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector;

@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface < JavaObject >

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients>)onOutputStreamWithJavaIoOutputStream:(JavaIoOutputStream *)outputStream;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface)

@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients < JavaObject >

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollectionArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy *)selectionStrategy
                                                                                                                                       withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)doNotEncrypt;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients)

@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms < JavaObject >

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy *)selectionStrategy
                                                                                                                                    withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)usingAlgorithmsWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)symmetricKeyAlgorithm
                                                                                                   withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil:(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)hashAlgorithmUtil
                                                                                                withLibComAfterlogicPgpAlgorithmCompressionAlgorithm:(LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)compressionAlgorithm;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)usingSecureAlgorithms;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms)

@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith < JavaObject >

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                                 withLibOrgBouncycastleOpenpgpPGPSecretKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                             withLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray:(IOSObjectArray *)keyRings;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy *)selectionStrategy
                                                                                                   withLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                                                          withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)doNotSign;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith)

@protocol LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor < JavaObject >

- (LibComAfterlogicPgpEncryption_signingEncryptionStream *)asciiArmor;

- (LibComAfterlogicPgpEncryption_signingEncryptionStream *)noArmor;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor)

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptionBuilderInterface_H
