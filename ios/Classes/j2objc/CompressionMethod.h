//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CompressionMethod.java
//

#ifndef CompressionMethod_H
#define CompressionMethod_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsCompressionMethod : NSObject
@property (readonly, class) jshort _null NS_SWIFT_NAME(_null);
@property (readonly, class) jshort DEFLATE NS_SWIFT_NAME(DEFLATE);

+ (jshort)_null;

+ (jshort)DEFLATE;

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsCompressionMethod)

inline jshort LibOrgBouncycastleCryptoTlsCompressionMethod_get__null(void);
#define LibOrgBouncycastleCryptoTlsCompressionMethod__null 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsCompressionMethod, _null, jshort)

inline jshort LibOrgBouncycastleCryptoTlsCompressionMethod_get_DEFLATE(void);
#define LibOrgBouncycastleCryptoTlsCompressionMethod_DEFLATE 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsCompressionMethod, DEFLATE, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsCompressionMethod_init(LibOrgBouncycastleCryptoTlsCompressionMethod *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCompressionMethod *new_LibOrgBouncycastleCryptoTlsCompressionMethod_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCompressionMethod *create_LibOrgBouncycastleCryptoTlsCompressionMethod_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsCompressionMethod)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CompressionMethod_H
