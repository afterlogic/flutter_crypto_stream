//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/OpenSSHPrivateKeySpec.java
//

#ifndef OpenSSHPrivateKeySpec_H
#define OpenSSHPrivateKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/EncodedKeySpec.h"

@class IOSByteArray;

@interface LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec : JavaSecuritySpecEncodedKeySpec

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encodedKey;

- (NSString *)getFormat;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec_initWithByteArray_(LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec *self, IOSByteArray *encodedKey);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec *new_LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec_initWithByteArray_(IOSByteArray *encodedKey) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec *create_LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec_initWithByteArray_(IOSByteArray *encodedKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OpenSSHPrivateKeySpec_H
