//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPOnePassSignature.java
//

#ifndef PGPOnePassSignature_H
#define PGPOnePassSignature_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoOutputStream;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgOnePassSignaturePacket;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPSignature;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider;

@interface LibOrgBouncycastleOpenpgpPGPOnePassSignature : NSObject

#pragma mark Public

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream;

- (IOSByteArray *)getEncoded;

- (jint)getHashAlgorithm;

- (jint)getKeyAlgorithm;

- (jlong)getKeyID;

- (jint)getSignatureType;

- (void)init__WithLibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentVerifierBuilderProvider>)verifierBuilderProvider
                                           withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey OBJC_METHOD_FAMILY_NONE;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)bytes;

- (void)updateWithByteArray:(IOSByteArray *)bytes
                    withInt:(jint)off
                    withInt:(jint)length;

- (jboolean)verifyWithLibOrgBouncycastleOpenpgpPGPSignature:(LibOrgBouncycastleOpenpgpPGPSignature *)pgpSig;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgOnePassSignaturePacket:(LibOrgBouncycastleBcpgOnePassSignaturePacket *)sigPack;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPOnePassSignature)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleOpenpgpPGPOnePassSignature *self, LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPOnePassSignature *new_LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPOnePassSignature *create_LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgOnePassSignaturePacket_(LibOrgBouncycastleOpenpgpPGPOnePassSignature *self, LibOrgBouncycastleBcpgOnePassSignaturePacket *sigPack);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPOnePassSignature *new_LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgOnePassSignaturePacket_(LibOrgBouncycastleBcpgOnePassSignaturePacket *sigPack) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPOnePassSignature *create_LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgOnePassSignaturePacket_(LibOrgBouncycastleBcpgOnePassSignaturePacket *sigPack);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPOnePassSignature)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPOnePassSignature_H
