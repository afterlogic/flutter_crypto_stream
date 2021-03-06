//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPEncryptedDataGenerator.java
//

#ifndef PGPEncryptedDataGenerator_H
#define PGPEncryptedDataGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "StreamGenerator.h"
#include "SymmetricKeyAlgorithmTags.h"

@class IOSByteArray;
@class JavaIoOutputStream;
@class LibOrgBouncycastleOpenpgpOperatorPGPKeyEncryptionMethodGenerator;
@protocol LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder;

@interface LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator : NSObject < LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags, LibOrgBouncycastleOpenpgpStreamGenerator >
@property (readonly, class) jint S2K_SHA1 NS_SWIFT_NAME(S2K_SHA1);
@property (readonly, class) jint S2K_SHA224 NS_SWIFT_NAME(S2K_SHA224);
@property (readonly, class) jint S2K_SHA256 NS_SWIFT_NAME(S2K_SHA256);
@property (readonly, class) jint S2K_SHA384 NS_SWIFT_NAME(S2K_SHA384);
@property (readonly, class) jint S2K_SHA512 NS_SWIFT_NAME(S2K_SHA512);

+ (jint)S2K_SHA1;

+ (jint)S2K_SHA224;

+ (jint)S2K_SHA256;

+ (jint)S2K_SHA384;

+ (jint)S2K_SHA512;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder>)encryptorBuilder;

- (instancetype __nonnull)initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder>)encryptorBuilder
                                                                               withBoolean:(jboolean)oldFormat;

- (void)addMethodWithLibOrgBouncycastleOpenpgpOperatorPGPKeyEncryptionMethodGenerator:(LibOrgBouncycastleOpenpgpOperatorPGPKeyEncryptionMethodGenerator *)method;

- (void)close;

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                     withByteArray:(IOSByteArray *)buffer;

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                          withLong:(jlong)length;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator)

inline jint LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_get_S2K_SHA1(void);
#define LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_S2K_SHA1 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator, S2K_SHA1, jint)

inline jint LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_get_S2K_SHA224(void);
#define LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_S2K_SHA224 11
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator, S2K_SHA224, jint)

inline jint LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_get_S2K_SHA256(void);
#define LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_S2K_SHA256 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator, S2K_SHA256, jint)

inline jint LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_get_S2K_SHA384(void);
#define LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_S2K_SHA384 9
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator, S2K_SHA384, jint)

inline jint LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_get_S2K_SHA512(void);
#define LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_S2K_SHA512 10
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator, S2K_SHA512, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *self, id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_withBoolean_(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *self, id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder, jboolean oldFormat);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_withBoolean_(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder, jboolean oldFormat) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder_withBoolean_(id<LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder> encryptorBuilder, jboolean oldFormat);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPEncryptedDataGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPEncryptedDataGenerator_H
