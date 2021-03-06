//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/WrappedGeneratorStream.java
//

#ifndef WrappedGeneratorStream_H
#define WrappedGeneratorStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/OutputStream.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleOpenpgpStreamGenerator;

@interface LibOrgBouncycastleOpenpgpWrappedGeneratorStream : JavaIoOutputStream

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
        withLibOrgBouncycastleOpenpgpStreamGenerator:(id<LibOrgBouncycastleOpenpgpStreamGenerator>)sGen;

- (void)close;

- (void)flush;

- (void)writeWithByteArray:(IOSByteArray *)bytes;

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)offset
                   withInt:(jint)length;

- (void)writeWithInt:(jint)b;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpWrappedGeneratorStream)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpWrappedGeneratorStream_initWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpStreamGenerator_(LibOrgBouncycastleOpenpgpWrappedGeneratorStream *self, JavaIoOutputStream *outArg, id<LibOrgBouncycastleOpenpgpStreamGenerator> sGen);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpWrappedGeneratorStream *new_LibOrgBouncycastleOpenpgpWrappedGeneratorStream_initWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpStreamGenerator_(JavaIoOutputStream *outArg, id<LibOrgBouncycastleOpenpgpStreamGenerator> sGen) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpWrappedGeneratorStream *create_LibOrgBouncycastleOpenpgpWrappedGeneratorStream_initWithJavaIoOutputStream_withLibOrgBouncycastleOpenpgpStreamGenerator_(JavaIoOutputStream *outArg, id<LibOrgBouncycastleOpenpgpStreamGenerator> sGen);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpWrappedGeneratorStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // WrappedGeneratorStream_H
