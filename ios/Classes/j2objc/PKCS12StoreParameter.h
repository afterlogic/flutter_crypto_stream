//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PKCS12StoreParameter.java
//

#ifndef PKCS12StoreParameter_H
#define PKCS12StoreParameter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/KeyStore.h"

@class IOSCharArray;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleJcajcePKCS12StoreParameter : NSObject < JavaSecurityKeyStore_LoadStoreParameter >

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                       withCharArray:(IOSCharArray *)password;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                       withCharArray:(IOSCharArray *)password
                                         withBoolean:(jboolean)forDEREncoding;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
        withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
        withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter
                                         withBoolean:(jboolean)forDEREncoding;

- (JavaIoOutputStream *)getOutputStream;

- (id<JavaSecurityKeyStore_ProtectionParameter>)getProtectionParameter;

- (jboolean)isForDEREncoding;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajcePKCS12StoreParameter)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(LibOrgBouncycastleJcajcePKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *new_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *create_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(LibOrgBouncycastleJcajcePKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *new_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *create_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(LibOrgBouncycastleJcajcePKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *new_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *create_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(LibOrgBouncycastleJcajcePKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *new_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKCS12StoreParameter *create_LibOrgBouncycastleJcajcePKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajcePKCS12StoreParameter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKCS12StoreParameter_H
