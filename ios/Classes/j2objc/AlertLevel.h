//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AlertLevel.java
//

#ifndef AlertLevel_H
#define AlertLevel_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsAlertLevel : NSObject
@property (readonly, class) jshort warning NS_SWIFT_NAME(warning);
@property (readonly, class) jshort fatal NS_SWIFT_NAME(fatal);

+ (jshort)warning;

+ (jshort)fatal;

#pragma mark Public

- (instancetype __nonnull)init;

+ (NSString *)getNameWithShort:(jshort)alertDescription;

+ (NSString *)getTextWithShort:(jshort)alertDescription;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsAlertLevel)

inline jshort LibOrgBouncycastleCryptoTlsAlertLevel_get_warning(void);
#define LibOrgBouncycastleCryptoTlsAlertLevel_warning 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsAlertLevel, warning, jshort)

inline jshort LibOrgBouncycastleCryptoTlsAlertLevel_get_fatal(void);
#define LibOrgBouncycastleCryptoTlsAlertLevel_fatal 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsAlertLevel, fatal, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAlertLevel_init(LibOrgBouncycastleCryptoTlsAlertLevel *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsAlertLevel *new_LibOrgBouncycastleCryptoTlsAlertLevel_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsAlertLevel *create_LibOrgBouncycastleCryptoTlsAlertLevel_init(void);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleCryptoTlsAlertLevel_getNameWithShort_(jshort alertDescription);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleCryptoTlsAlertLevel_getTextWithShort_(jshort alertDescription);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsAlertLevel)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AlertLevel_H
