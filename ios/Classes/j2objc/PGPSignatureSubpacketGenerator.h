//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPSignatureSubpacketGenerator.java
//

#ifndef PGPSignatureSubpacketGenerator_H
#define PGPSignatureSubpacketGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaUtilDate;
@class LibOrgBouncycastleOpenpgpPGPSignature;
@class LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector;
@protocol JavaUtilList;

@interface LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator : NSObject {
 @public
  id<JavaUtilList> list_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *)generate;

- (void)setEmbeddedSignatureWithBoolean:(jboolean)isCritical
withLibOrgBouncycastleOpenpgpPGPSignature:(LibOrgBouncycastleOpenpgpPGPSignature *)pgpSignature;

- (void)setExportableWithBoolean:(jboolean)isCritical
                     withBoolean:(jboolean)isExportable;

- (void)setFeatureWithBoolean:(jboolean)isCritical
                     withByte:(jbyte)feature;

- (void)setIssuerKeyIDWithBoolean:(jboolean)isCritical
                         withLong:(jlong)keyID;

- (void)setKeyExpirationTimeWithBoolean:(jboolean)isCritical
                               withLong:(jlong)seconds;

- (void)setKeyFlagsWithBoolean:(jboolean)isCritical
                       withInt:(jint)flags;

- (void)setNotationDataWithBoolean:(jboolean)isCritical
                       withBoolean:(jboolean)isHumanReadable
                      withNSString:(NSString *)notationName
                      withNSString:(NSString *)notationValue;

- (void)setPreferredCompressionAlgorithmsWithBoolean:(jboolean)isCritical
                                        withIntArray:(IOSIntArray *)algorithms;

- (void)setPreferredHashAlgorithmsWithBoolean:(jboolean)isCritical
                                 withIntArray:(IOSIntArray *)algorithms;

- (void)setPreferredSymmetricAlgorithmsWithBoolean:(jboolean)isCritical
                                      withIntArray:(IOSIntArray *)algorithms;

- (void)setPrimaryUserIDWithBoolean:(jboolean)isCritical
                        withBoolean:(jboolean)isPrimaryUserID;

- (void)setRevocableWithBoolean:(jboolean)isCritical
                    withBoolean:(jboolean)isRevocable;

- (void)setRevocationKeyWithBoolean:(jboolean)isCritical
                            withInt:(jint)keyAlgorithm
                      withByteArray:(IOSByteArray *)fingerprint;

- (void)setRevocationReasonWithBoolean:(jboolean)isCritical
                              withByte:(jbyte)reason
                          withNSString:(NSString *)description_;

- (void)setSignatureCreationTimeWithBoolean:(jboolean)isCritical
                           withJavaUtilDate:(JavaUtilDate *)date;

- (void)setSignatureExpirationTimeWithBoolean:(jboolean)isCritical
                                     withLong:(jlong)seconds;

- (void)setSignatureTargetWithBoolean:(jboolean)isCritical
                              withInt:(jint)publicKeyAlgorithm
                              withInt:(jint)hashAlgorithm
                        withByteArray:(IOSByteArray *)hashData;

- (void)setSignerUserIDWithBoolean:(jboolean)isCritical
                     withByteArray:(IOSByteArray *)rawUserID;

- (void)setSignerUserIDWithBoolean:(jboolean)isCritical
                      withNSString:(NSString *)userID;

- (void)setTrustWithBoolean:(jboolean)isCritical
                    withInt:(jint)depth
                    withInt:(jint)trustAmount;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator, list_, id<JavaUtilList>)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_init(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *new_LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *create_LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPSignatureSubpacketGenerator_H
