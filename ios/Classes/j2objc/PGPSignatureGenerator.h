//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSignatureGenerator.java
//

#ifndef PGPSignatureGenerator_H
#define PGPSignatureGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleOpenpgpPGPOnePassSignature;
@class LibOrgBouncycastleOpenpgpPGPPrivateKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSignature;
@class LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;
@class LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder;

@interface LibOrgBouncycastleOpenpgpPGPSignatureGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>)contentSignerBuilder;

- (LibOrgBouncycastleOpenpgpPGPSignature *)generate;

- (LibOrgBouncycastleOpenpgpPGPSignature *)generateCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (LibOrgBouncycastleOpenpgpPGPSignature *)generateCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey
                                                                withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (LibOrgBouncycastleOpenpgpPGPSignature *)generateCertificationWithLibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector:(LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector *)userAttributes
                                                                                   withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (LibOrgBouncycastleOpenpgpPGPSignature *)generateCertificationWithNSString:(NSString *)id_
                                   withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey;

- (LibOrgBouncycastleOpenpgpPGPOnePassSignature *)generateOnePassVersionWithBoolean:(jboolean)isNested;

- (void)init__WithInt:(jint)signatureType
withLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)key OBJC_METHOD_FAMILY_NONE;

- (void)setHashedSubpacketsWithLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)hashedPcks;

- (void)setUnhashedSubpacketsWithLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector:(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)unhashedPcks;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)b;

- (void)updateWithByteArray:(IOSByteArray *)b
                    withInt:(jint)off
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPSignatureGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(LibOrgBouncycastleOpenpgpPGPSignatureGenerator *self, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignatureGenerator *new_LibOrgBouncycastleOpenpgpPGPSignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignatureGenerator *create_LibOrgBouncycastleOpenpgpPGPSignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPSignatureGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPSignatureGenerator_H
