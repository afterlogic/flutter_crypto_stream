//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ElGamalSecretBCPGKey.java
//

#ifndef ElGamalSecretBCPGKey_H
#define ElGamalSecretBCPGKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BCPGKey.h"
#include "BCPGObject.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@class LibOrgBouncycastleBcpgMPInteger;

@interface LibOrgBouncycastleBcpgElGamalSecretBCPGKey : LibOrgBouncycastleBcpgBCPGObject < LibOrgBouncycastleBcpgBCPGKey > {
 @public
  LibOrgBouncycastleBcpgMPInteger *x_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (JavaMathBigInteger *)getX;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgElGamalSecretBCPGKey)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgElGamalSecretBCPGKey, x_, LibOrgBouncycastleBcpgMPInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgElGamalSecretBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgElGamalSecretBCPGKey *new_LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgElGamalSecretBCPGKey *create_LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithJavaMathBigInteger_(LibOrgBouncycastleBcpgElGamalSecretBCPGKey *self, JavaMathBigInteger *x);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgElGamalSecretBCPGKey *new_LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithJavaMathBigInteger_(JavaMathBigInteger *x) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgElGamalSecretBCPGKey *create_LibOrgBouncycastleBcpgElGamalSecretBCPGKey_initWithJavaMathBigInteger_(JavaMathBigInteger *x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgElGamalSecretBCPGKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ElGamalSecretBCPGKey_H
