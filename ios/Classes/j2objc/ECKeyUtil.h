//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/ECKeyUtil.java
//

#ifndef ECKeyUtil_H
#define ECKeyUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityProvider;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastleJceECKeyUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (id<JavaSecurityPrivateKey>)privateToExplicitParametersWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                           withJavaSecurityProvider:(JavaSecurityProvider *)provider;

+ (id<JavaSecurityPrivateKey>)privateToExplicitParametersWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key
                                                                       withNSString:(NSString *)providerName;

+ (id<JavaSecurityPublicKey>)publicToExplicitParametersWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                                                        withJavaSecurityProvider:(JavaSecurityProvider *)provider;

+ (id<JavaSecurityPublicKey>)publicToExplicitParametersWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key
                                                                    withNSString:(NSString *)providerName;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceECKeyUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJceECKeyUtil_init(LibOrgBouncycastleJceECKeyUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceECKeyUtil *new_LibOrgBouncycastleJceECKeyUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceECKeyUtil *create_LibOrgBouncycastleJceECKeyUtil_init(void);

FOUNDATION_EXPORT id<JavaSecurityPublicKey> LibOrgBouncycastleJceECKeyUtil_publicToExplicitParametersWithJavaSecurityPublicKey_withNSString_(id<JavaSecurityPublicKey> key, NSString *providerName);

FOUNDATION_EXPORT id<JavaSecurityPublicKey> LibOrgBouncycastleJceECKeyUtil_publicToExplicitParametersWithJavaSecurityPublicKey_withJavaSecurityProvider_(id<JavaSecurityPublicKey> key, JavaSecurityProvider *provider);

FOUNDATION_EXPORT id<JavaSecurityPrivateKey> LibOrgBouncycastleJceECKeyUtil_privateToExplicitParametersWithJavaSecurityPrivateKey_withNSString_(id<JavaSecurityPrivateKey> key, NSString *providerName);

FOUNDATION_EXPORT id<JavaSecurityPrivateKey> LibOrgBouncycastleJceECKeyUtil_privateToExplicitParametersWithJavaSecurityPrivateKey_withJavaSecurityProvider_(id<JavaSecurityPrivateKey> key, JavaSecurityProvider *provider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceECKeyUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECKeyUtil_H