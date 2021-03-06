//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/SSHBuffer.java
//

#ifndef SSHBuffer_H
#define SSHBuffer_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;

@interface LibOrgBouncycastleCryptoUtilSSHBuffer : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)buffer;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)magic
                              withByteArray:(IOSByteArray *)buffer;

- (IOSByteArray *)getBuffer;

- (jboolean)hasRemaining;

- (JavaMathBigInteger *)positiveBigNum;

- (IOSByteArray *)readPaddedString;

- (IOSByteArray *)readString;

- (jint)readU32;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoUtilSSHBuffer)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_withByteArray_(LibOrgBouncycastleCryptoUtilSSHBuffer *self, IOSByteArray *magic, IOSByteArray *buffer);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilSSHBuffer *new_LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_withByteArray_(IOSByteArray *magic, IOSByteArray *buffer) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilSSHBuffer *create_LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_withByteArray_(IOSByteArray *magic, IOSByteArray *buffer);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_(LibOrgBouncycastleCryptoUtilSSHBuffer *self, IOSByteArray *buffer);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilSSHBuffer *new_LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_(IOSByteArray *buffer) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoUtilSSHBuffer *create_LibOrgBouncycastleCryptoUtilSSHBuffer_initWithByteArray_(IOSByteArray *buffer);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoUtilSSHBuffer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SSHBuffer_H
