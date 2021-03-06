//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/X931Signer.java
//

#ifndef X931Signer_H
#define X931Signer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Signer.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoAsymmetricBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoSignersX931Signer : NSObject < LibOrgBouncycastleCryptoSigner >
@property (readonly, class) jint TRAILER_IMPLICIT NS_SWIFT_NAME(TRAILER_IMPLICIT);
@property (readonly, class) jint TRAILER_RIPEMD160 NS_SWIFT_NAME(TRAILER_RIPEMD160);
@property (readonly, class) jint TRAILER_RIPEMD128 NS_SWIFT_NAME(TRAILER_RIPEMD128);
@property (readonly, class) jint TRAILER_SHA1 NS_SWIFT_NAME(TRAILER_SHA1);
@property (readonly, class) jint TRAILER_SHA256 NS_SWIFT_NAME(TRAILER_SHA256);
@property (readonly, class) jint TRAILER_SHA512 NS_SWIFT_NAME(TRAILER_SHA512);
@property (readonly, class) jint TRAILER_SHA384 NS_SWIFT_NAME(TRAILER_SHA384);
@property (readonly, class) jint TRAILER_WHIRLPOOL NS_SWIFT_NAME(TRAILER_WHIRLPOOL);
@property (readonly, class) jint TRAILER_SHA224 NS_SWIFT_NAME(TRAILER_SHA224);

+ (jint)TRAILER_IMPLICIT;

+ (jint)TRAILER_RIPEMD160;

+ (jint)TRAILER_RIPEMD128;

+ (jint)TRAILER_SHA1;

+ (jint)TRAILER_SHA256;

+ (jint)TRAILER_SHA512;

+ (jint)TRAILER_SHA384;

+ (jint)TRAILER_WHIRLPOOL;

+ (jint)TRAILER_SHA224;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher
                                             withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher
                                             withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                                                    withBoolean:(jboolean)implicit;

- (IOSByteArray *)generateSignature;

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)b;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)off
                    withInt:(jint)len;

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersX931Signer)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_IMPLICIT(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_IMPLICIT 188
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_IMPLICIT, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_RIPEMD160(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_RIPEMD160 12748
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_RIPEMD160, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_RIPEMD128(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_RIPEMD128 13004
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_RIPEMD128, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_SHA1(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_SHA1 13260
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_SHA1, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_SHA256(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_SHA256 13516
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_SHA256, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_SHA512(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_SHA512 13772
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_SHA512, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_SHA384(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_SHA384 14028
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_SHA384, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_WHIRLPOOL(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_WHIRLPOOL 14284
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_WHIRLPOOL, jint)

inline jint LibOrgBouncycastleCryptoSignersX931Signer_get_TRAILER_SHA224(void);
#define LibOrgBouncycastleCryptoSignersX931Signer_TRAILER_SHA224 14540
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersX931Signer, TRAILER_SHA224, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(LibOrgBouncycastleCryptoSignersX931Signer *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersX931Signer *new_LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersX931Signer *create_LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_withBoolean_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest, jboolean implicit);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoSignersX931Signer *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersX931Signer *new_LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersX931Signer *create_LibOrgBouncycastleCryptoSignersX931Signer_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_withLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher, id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersX931Signer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X931Signer_H
