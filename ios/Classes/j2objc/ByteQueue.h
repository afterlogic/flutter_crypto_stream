//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ByteQueue.java
//

#ifndef ByteQueue_H
#define ByteQueue_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoByteArrayInputStream;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleCryptoTlsByteQueue : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)buf
                                    withInt:(jint)off
                                    withInt:(jint)len;

- (instancetype __nonnull)initWithInt:(jint)capacity;

- (void)addDataWithByteArray:(IOSByteArray *)buf
                     withInt:(jint)off
                     withInt:(jint)len;

- (jint)available;

- (void)copyToWithJavaIoOutputStream:(JavaIoOutputStream *)output
                             withInt:(jint)length OBJC_METHOD_FAMILY_NONE;

+ (jint)nextTwoPowWithInt:(jint)i;

- (void)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)offset
                  withInt:(jint)len
                  withInt:(jint)skip;

- (JavaIoByteArrayInputStream *)readFromWithInt:(jint)length;

- (void)removeDataWithByteArray:(IOSByteArray *)buf
                        withInt:(jint)off
                        withInt:(jint)len
                        withInt:(jint)skip;

- (void)removeDataWithInt:(jint)i;

- (IOSByteArray *)removeDataWithInt:(jint)len
                            withInt:(jint)skip;

- (void)shrink;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsByteQueue)

FOUNDATION_EXPORT jint LibOrgBouncycastleCryptoTlsByteQueue_nextTwoPowWithInt_(jint i);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsByteQueue_init(LibOrgBouncycastleCryptoTlsByteQueue *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *new_LibOrgBouncycastleCryptoTlsByteQueue_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *create_LibOrgBouncycastleCryptoTlsByteQueue_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsByteQueue_initWithInt_(LibOrgBouncycastleCryptoTlsByteQueue *self, jint capacity);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *new_LibOrgBouncycastleCryptoTlsByteQueue_initWithInt_(jint capacity) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *create_LibOrgBouncycastleCryptoTlsByteQueue_initWithInt_(jint capacity);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsByteQueue_initWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoTlsByteQueue *self, IOSByteArray *buf, jint off, jint len);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *new_LibOrgBouncycastleCryptoTlsByteQueue_initWithByteArray_withInt_withInt_(IOSByteArray *buf, jint off, jint len) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsByteQueue *create_LibOrgBouncycastleCryptoTlsByteQueue_initWithByteArray_withInt_withInt_(IOSByteArray *buf, jint off, jint len);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsByteQueue)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ByteQueue_H
