//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/digest/Tiger.java
//

#ifndef Tiger_H
#define Tiger_H

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
#include "PBESecretKeyFactory.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleCryptoCipherKeyGenerator;
@protocol LibOrgBouncycastleCryptoDigest;
@protocol LibOrgBouncycastleCryptoMac;
@protocol LibOrgBouncycastleJcajceProviderConfigConfigurableProvider;

@interface LibOrgBouncycastleJcajceProviderDigestTiger : NSObject

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_Digest : LibOrgBouncycastleJcajceProviderDigestBCMessageDigest < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_Digest)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_Digest_init(LibOrgBouncycastleJcajceProviderDigestTiger_Digest *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_Digest *new_LibOrgBouncycastleJcajceProviderDigestTiger_Digest_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_Digest *create_LibOrgBouncycastleJcajceProviderDigestTiger_Digest_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_Digest)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_HashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_HashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_HashMac_init(LibOrgBouncycastleJcajceProviderDigestTiger_HashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_HashMac *new_LibOrgBouncycastleJcajceProviderDigestTiger_HashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_HashMac *create_LibOrgBouncycastleJcajceProviderDigestTiger_HashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_HashMac)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseKeyGenerator

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                                   withInt:(jint)arg1
withLibOrgBouncycastleCryptoCipherKeyGenerator:(LibOrgBouncycastleCryptoCipherKeyGenerator *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator_init(LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator *new_LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator *create_LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_KeyGenerator)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac_init(LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac *new_LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac *create_LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_TigerHmac)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory : LibOrgBouncycastleJcajceProviderSymmetricUtilPBESecretKeyFactory

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg1
                               withBoolean:(jboolean)arg2
                                   withInt:(jint)arg3
                                   withInt:(jint)arg4
                                   withInt:(jint)arg5
                                   withInt:(jint)arg6 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory_init(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory *new_LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory *create_LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithMacKeyFactory)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac : LibOrgBouncycastleJcajceProviderSymmetricUtilBaseMac

#pragma mark Public

- (instancetype __nonnull)init;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)arg0
                                                      withInt:(jint)arg1
                                                      withInt:(jint)arg2
                                                      withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac_init(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac *new_LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac *create_LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_PBEWithHashMac)

@interface LibOrgBouncycastleJcajceProviderDigestTiger_Mappings : LibOrgBouncycastleJcajceProviderDigestDigestAlgorithmProvider

#pragma mark Public

- (instancetype __nonnull)init;

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderDigestTiger_Mappings)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderDigestTiger_Mappings_init(LibOrgBouncycastleJcajceProviderDigestTiger_Mappings *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_Mappings *new_LibOrgBouncycastleJcajceProviderDigestTiger_Mappings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderDigestTiger_Mappings *create_LibOrgBouncycastleJcajceProviderDigestTiger_Mappings_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderDigestTiger_Mappings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Tiger_H
