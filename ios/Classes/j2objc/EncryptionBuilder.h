//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/encryption_signing/EncryptionBuilder.java
//

#ifndef EncryptionBuilder_H
#define EncryptionBuilder_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "EncryptionBuilderInterface.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaIoOutputStream;
@class LibComAfterlogicPgpAlgorithmCompressionAlgorithm;
@class LibComAfterlogicPgpAlgorithmHashAlgorithmUtil;
@class LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;
@class LibComAfterlogicPgpEncryption_signingEncryptionStream;
@class LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy;
@class LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy;
@class LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy;
@class LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy;
@class LibComAfterlogicPgpUtilMultiMap;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;
@protocol LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector;

@interface LibComAfterlogicPgpEncryption_signingEncryptionBuilder : NSObject < LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface >

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients>)onOutputStreamWithJavaIoOutputStream:(JavaIoOutputStream *)outputStream;

#pragma mark Package-Private

- (LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *)encryptionKeySelector;

- (LibComAfterlogicPgpKeySelectionKeySecretKeySelectionStrategy *)signingKeySelector;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilder)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionBuilder_init(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *self);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder *new_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder *create_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilder)

@interface LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl : NSObject < LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_ToRecipients >

#pragma mark Public

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)doNotEncrypt;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipients;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollectionArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)toRecipientsWithLibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy *)ringSelectionStrategy
                                                                                                                                       withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder:(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *)outer$;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl *self, LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl *new_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl *create_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ToRecipientsImpl)

@interface LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl : NSObject < LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms >

#pragma mark Public

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_WithAlgorithms>)andToSelfWithLibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy *)ringSelectionStrategy
                                                                                                                                    withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)usingAlgorithmsWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)symmetricKeyAlgorithm
                                                                                                   withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil:(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)hashAlgorithmUtil
                                                                                                withLibComAfterlogicPgpAlgorithmCompressionAlgorithm:(LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)compressionAlgorithm;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith>)usingSecureAlgorithms;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder:(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *)outer$;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl *self, LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl *new_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl *create_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_WithAlgorithmsImpl)

@interface LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl : NSObject < LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_SignWith >

#pragma mark Public

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)doNotSign;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                                 withLibOrgBouncycastleOpenpgpPGPSecretKeyArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                             withLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray:(IOSObjectArray *)keys;

- (id<LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor>)signWithWithLibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy:(LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy *)ringSelectionStrategy
                                                                                                   withLibComAfterlogicPgpKeyProtectionSecretKeyRingProtector:(id<LibComAfterlogicPgpKeyProtectionSecretKeyRingProtector>)decryptor
                                                                                                                          withLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)keys;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder:(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *)outer$;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl *self, LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl *new_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl *create_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_SignWithImpl)

@interface LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl : NSObject < LibComAfterlogicPgpEncryption_signingEncryptionBuilderInterface_Armor >

#pragma mark Public

- (LibComAfterlogicPgpEncryption_signingEncryptionStream *)asciiArmor;

- (LibComAfterlogicPgpEncryption_signingEncryptionStream *)noArmor;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder:(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *)outer$;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl *self, LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl *new_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl *create_LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl_initWithLibComAfterlogicPgpEncryption_signingEncryptionBuilder_(LibComAfterlogicPgpEncryption_signingEncryptionBuilder *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionBuilder_ArmorImpl)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptionBuilder_H
