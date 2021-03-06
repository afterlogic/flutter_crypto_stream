//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/util/jcaJceUtilDigestFactory.java
//

#ifndef JcaJceUtilDigestFactory_H
#define JcaJceUtilDigestFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (id<LibOrgBouncycastleCryptoDigest>)getDigestWithNSString:(NSString *)digestName;

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)digestName;

+ (jboolean)isSameDigestWithNSString:(NSString *)digest1
                        withNSString:(NSString *)digest2;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *new_LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *create_LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init(void);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoDigest> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getDigestWithNSString_(NSString *digestName);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_isSameDigestWithNSString_withNSString_(NSString *digest1, NSString *digest2);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_(NSString *digestName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory)

@compatibility_alias LibOrgBouncycastleJcajceProviderUtilJcaJceUtilDigestFactory LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory;


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaJceUtilDigestFactory_H
