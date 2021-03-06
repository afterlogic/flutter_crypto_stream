//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/io/JcajceIoMacOutputStream.java
//

#ifndef JcajceIoMacOutputStream_H
#define JcajceIoMacOutputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/OutputStream.h"

@class IOSByteArray;
@class JavaxCryptoMac;

@interface LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream : JavaIoOutputStream

#pragma mark Public

- (instancetype __nonnull)initWithJavaxCryptoMac:(JavaxCryptoMac *)mac;

- (IOSByteArray *)getMac;

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithInt:(jint)b;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream_initWithJavaxCryptoMac_(LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream *self, JavaxCryptoMac *mac);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream *new_LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream_initWithJavaxCryptoMac_(JavaxCryptoMac *mac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream *create_LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream_initWithJavaxCryptoMac_(JavaxCryptoMac *mac);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceIoJcajceIoMacOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceIoMacOutputStream_H
