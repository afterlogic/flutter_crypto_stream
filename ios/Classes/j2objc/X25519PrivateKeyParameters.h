//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/X25519PrivateKeyParameters.java
//

#ifndef X25519PrivateKeyParameters_H
#define X25519PrivateKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters;

@interface LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter
@property (readonly, class) jint KEY_SIZE NS_SWIFT_NAME(KEY_SIZE);
@property (readonly, class) jint SECRET_SIZE NS_SWIFT_NAME(SECRET_SIZE);

+ (jint)KEY_SIZE;

+ (jint)SECRET_SIZE;

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)buf
                                    withInt:(jint)off;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input;

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)encodeWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off;

- (LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *)generatePublicKey;

- (void)generateSecretWithLibOrgBouncycastleCryptoParamsX25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsX25519PublicKeyParameters *)publicKey
                                                                    withByteArray:(IOSByteArray *)buf
                                                                          withInt:(jint)off;

- (IOSByteArray *)getEncoded;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters)

inline jint LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_get_KEY_SIZE(void);
#define LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_KEY_SIZE 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, KEY_SIZE, jint)

inline jint LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_get_SECRET_SIZE(void);
#define LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_SECRET_SIZE 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters, SECRET_SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, IOSByteArray *buf, jint off);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *self, JavaIoInputStream *input);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsX25519PrivateKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X25519PrivateKeyParameters_H
