//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/NameType.java
//

#ifndef NameType_H
#define NameType_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsNameType : NSObject
@property (readonly, class) jshort host_name NS_SWIFT_NAME(host_name);

+ (jshort)host_name;

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)isValidWithShort:(jshort)nameType;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsNameType)

inline jshort LibOrgBouncycastleCryptoTlsNameType_get_host_name(void);
#define LibOrgBouncycastleCryptoTlsNameType_host_name 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsNameType, host_name, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsNameType_init(LibOrgBouncycastleCryptoTlsNameType *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsNameType *new_LibOrgBouncycastleCryptoTlsNameType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsNameType *create_LibOrgBouncycastleCryptoTlsNameType_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoTlsNameType_isValidWithShort_(jshort nameType);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsNameType)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NameType_H
