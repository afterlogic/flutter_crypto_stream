//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/ISOTrailers.java
//

#ifndef ISOTrailers_H
#define ISOTrailers_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaLangInteger;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoSignersISOTrailers : NSObject
@property (readonly, class) jint TRAILER_IMPLICIT NS_SWIFT_NAME(TRAILER_IMPLICIT);
@property (readonly, class) jint TRAILER_RIPEMD160 NS_SWIFT_NAME(TRAILER_RIPEMD160);
@property (readonly, class) jint TRAILER_RIPEMD128 NS_SWIFT_NAME(TRAILER_RIPEMD128);
@property (readonly, class) jint TRAILER_SHA1 NS_SWIFT_NAME(TRAILER_SHA1);
@property (readonly, class) jint TRAILER_SHA256 NS_SWIFT_NAME(TRAILER_SHA256);
@property (readonly, class) jint TRAILER_SHA512 NS_SWIFT_NAME(TRAILER_SHA512);
@property (readonly, class) jint TRAILER_SHA384 NS_SWIFT_NAME(TRAILER_SHA384);
@property (readonly, class) jint TRAILER_WHIRLPOOL NS_SWIFT_NAME(TRAILER_WHIRLPOOL);
@property (readonly, class) jint TRAILER_SHA224 NS_SWIFT_NAME(TRAILER_SHA224);
@property (readonly, class) jint TRAILER_SHA512_224 NS_SWIFT_NAME(TRAILER_SHA512_224);
@property (readonly, class) jint TRAILER_SHA512_256 NS_SWIFT_NAME(TRAILER_SHA512_256);

+ (jint)TRAILER_IMPLICIT;

+ (jint)TRAILER_RIPEMD160;

+ (jint)TRAILER_RIPEMD128;

+ (jint)TRAILER_SHA1;

+ (jint)TRAILER_SHA256;

+ (jint)TRAILER_SHA512;

+ (jint)TRAILER_SHA384;

+ (jint)TRAILER_WHIRLPOOL;

+ (jint)TRAILER_SHA224;

+ (jint)TRAILER_SHA512_224;

+ (jint)TRAILER_SHA512_256;

#pragma mark Public

- (instancetype __nonnull)init;

+ (JavaLangInteger *)getTrailerWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

+ (jboolean)noTrailerAvailableWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoSignersISOTrailers)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_IMPLICIT(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT 188
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_IMPLICIT, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_RIPEMD160(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_RIPEMD160 12748
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_RIPEMD160, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_RIPEMD128(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_RIPEMD128 13004
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_RIPEMD128, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA1(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA1 13260
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA1, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA256(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA256 13516
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA256, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA512(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA512 13772
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA512, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA384(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA384 14028
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA384, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_WHIRLPOOL(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_WHIRLPOOL 14284
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_WHIRLPOOL, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA224(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA224 14540
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA224, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA512_224(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA512_224 14796
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA512_224, jint)

inline jint LibOrgBouncycastleCryptoSignersISOTrailers_get_TRAILER_SHA512_256(void);
#define LibOrgBouncycastleCryptoSignersISOTrailers_TRAILER_SHA512_256 15052
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoSignersISOTrailers, TRAILER_SHA512_256, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoSignersISOTrailers_init(LibOrgBouncycastleCryptoSignersISOTrailers *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersISOTrailers *new_LibOrgBouncycastleCryptoSignersISOTrailers_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoSignersISOTrailers *create_LibOrgBouncycastleCryptoSignersISOTrailers_init(void);

FOUNDATION_EXPORT JavaLangInteger *LibOrgBouncycastleCryptoSignersISOTrailers_getTrailerWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoSignersISOTrailers_noTrailerAvailableWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersISOTrailers)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ISOTrailers_H
