//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/BulkCipherAlgorithm.java
//

#ifndef BulkCipherAlgorithm_H
#define BulkCipherAlgorithm_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm : NSObject
@property (readonly, class) jint _null NS_SWIFT_NAME(_null);
@property (readonly, class) jint rc4 NS_SWIFT_NAME(rc4);
@property (readonly, class) jint rc2 NS_SWIFT_NAME(rc2);
@property (readonly, class) jint des NS_SWIFT_NAME(des);
@property (readonly, class) jint _3des NS_SWIFT_NAME(_3des);
@property (readonly, class) jint des40 NS_SWIFT_NAME(des40);
@property (readonly, class) jint aes NS_SWIFT_NAME(aes);
@property (readonly, class) jint idea NS_SWIFT_NAME(idea);

+ (jint)_null;

+ (jint)rc4;

+ (jint)rc2;

+ (jint)des;

+ (jint)_3des;

+ (jint)des40;

+ (jint)aes;

+ (jint)idea;

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get__null(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm__null 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, _null, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_rc4(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_rc4 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, rc4, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_rc2(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_rc2 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, rc2, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_des(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_des 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, des, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get__3des(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm__3des 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, _3des, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_des40(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_des40 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, des40, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_aes(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_aes 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, aes, jint)

inline jint LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_get_idea(void);
#define LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_idea 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm, idea, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_init(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm *new_LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm *create_LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsBulkCipherAlgorithm)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BulkCipherAlgorithm_H
