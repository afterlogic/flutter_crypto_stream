//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/SHA3.java
//

#ifndef SHA3_H
#define SHA3_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BCMessageDigest.h"
#include "BaseKeyGenerator.h"
#include "BaseMac.h"
#include "DigestAlgorithmProvider.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoDigest;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderDigestSHA3 : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3 : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)size;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3_initWithInt_(LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3 *self, jint size);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)size;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3_initWithInt_(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3 *self, jint size);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3 : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)size;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3_initWithInt_(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3 *self, jint size);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224 : LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224_init(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256 : LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256_init(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384 : LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384_init(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest384)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512 : LibOrgBouncycastleJcajceProviderDigestSHA3_DigestSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512_init(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_Digest512)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224 : LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224_init(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256 : LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256_init(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384 : LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384_init(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac384)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512 : LibOrgBouncycastleJcajceProviderDigestSHA3_HashMacSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512_init(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_HashMac512)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224 : LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224_init(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator224)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256 : LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256_init(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator256)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384 : LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384_init(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator384)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512 : LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGeneratorSHA3

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512_init(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512 *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512 *new_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512 *create_LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_KeyGenerator512)

@interface LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings_init(LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings *new_LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings *create_LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestSHA3_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SHA3_H
