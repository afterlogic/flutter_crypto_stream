//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/DataLengthException.java
//

#ifndef DataLengthException_H
#define DataLengthException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "RuntimeCryptoException.h"

@interface LibOrgBouncycastleCryptoDataLengthException : LibOrgBouncycastleCryptoRuntimeCryptoException

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithNSString:(NSString *)message;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoDataLengthException)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDataLengthException_init(LibOrgBouncycastleCryptoDataLengthException *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDataLengthException *new_LibOrgBouncycastleCryptoDataLengthException_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDataLengthException *create_LibOrgBouncycastleCryptoDataLengthException_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(LibOrgBouncycastleCryptoDataLengthException *self, NSString *message);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDataLengthException *new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(NSString *message) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoDataLengthException *create_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(NSString *message);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoDataLengthException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DataLengthException_H
