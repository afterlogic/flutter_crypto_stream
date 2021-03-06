//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/io/CipherOutputStream.java
//

#ifndef CipherOutputStream_H
#define CipherOutputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/FilterOutputStream.h"

@class IOSByteArray;
@class JavaIoOutputStream;
@class JavaxCryptoCipher;

@interface LibOrgBouncycastleJcajceIoCipherOutputStream : JavaIoFilterOutputStream

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)output
                               withJavaxCryptoCipher:(JavaxCryptoCipher *)cipher;

- (void)close;

- (void)flush;

- (void)writeWithByteArray:(IOSByteArray *)b
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithInt:(jint)b;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceIoCipherOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceIoCipherOutputStream_initWithJavaIoOutputStream_withJavaxCryptoCipher_(LibOrgBouncycastleJcajceIoCipherOutputStream *self, JavaIoOutputStream *output, JavaxCryptoCipher *cipher);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoCipherOutputStream *new_LibOrgBouncycastleJcajceIoCipherOutputStream_initWithJavaIoOutputStream_withJavaxCryptoCipher_(JavaIoOutputStream *output, JavaxCryptoCipher *cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoCipherOutputStream *create_LibOrgBouncycastleJcajceIoCipherOutputStream_initWithJavaIoOutputStream_withJavaxCryptoCipher_(JavaIoOutputStream *output, JavaxCryptoCipher *cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceIoCipherOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CipherOutputStream_H
