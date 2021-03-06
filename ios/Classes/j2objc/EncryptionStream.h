//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/encryption_signing/EncryptionStream.java
//

#ifndef EncryptionStream_H
#define EncryptionStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/OutputStream.h"

@class IOSByteArray;
@class LibComAfterlogicPgpAlgorithmCompressionAlgorithm;
@class LibComAfterlogicPgpAlgorithmHashAlgorithmUtil;
@class LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;
@class LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata;
@protocol JavaUtilSet;

@interface LibComAfterlogicPgpEncryption_signingEncryptionStream : JavaIoOutputStream

#pragma mark Public

- (void)close;

- (void)flush;

- (LibComAfterlogicPgpDecryption_verificationOpenPgpMetadata *)getResult;

- (void)writeWithByteArray:(IOSByteArray *)buffer;

- (void)writeWithByteArray:(IOSByteArray *)buffer
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithInt:(jint)data;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)targetOutputStream
                                     withJavaUtilSet:(id<JavaUtilSet>)encryptionKeys
                                     withJavaUtilSet:(id<JavaUtilSet>)signingKeys
withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm:(LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *)symmetricKeyAlgorithm
   withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil:(LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *)hashAlgorithmUtil
withLibComAfterlogicPgpAlgorithmCompressionAlgorithm:(LibComAfterlogicPgpAlgorithmCompressionAlgorithm *)compressionAlgorithm
                                         withBoolean:(jboolean)asciiArmor;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpEncryption_signingEncryptionStream)

FOUNDATION_EXPORT void LibComAfterlogicPgpEncryption_signingEncryptionStream_initWithJavaIoOutputStream_withJavaUtilSet_withJavaUtilSet_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_(LibComAfterlogicPgpEncryption_signingEncryptionStream *self, JavaIoOutputStream *targetOutputStream, id<JavaUtilSet> encryptionKeys, id<JavaUtilSet> signingKeys, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *compressionAlgorithm, jboolean asciiArmor);

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionStream *new_LibComAfterlogicPgpEncryption_signingEncryptionStream_initWithJavaIoOutputStream_withJavaUtilSet_withJavaUtilSet_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_(JavaIoOutputStream *targetOutputStream, id<JavaUtilSet> encryptionKeys, id<JavaUtilSet> signingKeys, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *compressionAlgorithm, jboolean asciiArmor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpEncryption_signingEncryptionStream *create_LibComAfterlogicPgpEncryption_signingEncryptionStream_initWithJavaIoOutputStream_withJavaUtilSet_withJavaUtilSet_withLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm_withLibComAfterlogicPgpAlgorithmHashAlgorithmUtil_withLibComAfterlogicPgpAlgorithmCompressionAlgorithm_withBoolean_(JavaIoOutputStream *targetOutputStream, id<JavaUtilSet> encryptionKeys, id<JavaUtilSet> signingKeys, LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *symmetricKeyAlgorithm, LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *hashAlgorithmUtil, LibComAfterlogicPgpAlgorithmCompressionAlgorithm *compressionAlgorithm, jboolean asciiArmor);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpEncryption_signingEncryptionStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EncryptionStream_H
