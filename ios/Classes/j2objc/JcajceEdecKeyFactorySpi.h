//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/edec/JcajceEdecKeyFactorySpi.java
//

#ifndef JcajceEdecKeyFactorySpi_H
#define JcajceEdecKeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyInfoConverter.h"
#include "BaseKeyFactorySpi.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSClass;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi < LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter > {
 @public
  NSString *algorithm_;
}
@property (readonly, class) IOSByteArray *x448Prefix NS_SWIFT_NAME(x448Prefix);
@property (readonly, class) IOSByteArray *x25519Prefix NS_SWIFT_NAME(x25519Prefix);
@property (readonly, class) IOSByteArray *Ed448Prefix NS_SWIFT_NAME(Ed448Prefix);
@property (readonly, class) IOSByteArray *Ed25519Prefix NS_SWIFT_NAME(Ed25519Prefix);

+ (IOSByteArray *)x448Prefix;

+ (IOSByteArray *)x25519Prefix;

+ (IOSByteArray *)Ed448Prefix;

+ (IOSByteArray *)Ed25519Prefix;

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
                               withBoolean:(jboolean)isXdh
                                   withInt:(jint)specificBase;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, algorithm_, NSString *)

inline IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_x448Prefix(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, x448Prefix, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_x25519Prefix(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, x25519Prefix, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_Ed448Prefix(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, Ed448Prefix, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_Ed25519Prefix(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, Ed25519Prefix, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *self, NSString *algorithm, jboolean isXdh, jint specificBase);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(NSString *algorithm, jboolean isXdh, jint specificBase) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(NSString *algorithm, jboolean isXdh, jint specificBase);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448)

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 : LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                               withBoolean:(jboolean)arg1
                                   withInt:(jint)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceEdecKeyFactorySpi_H
