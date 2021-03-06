//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/jcajce/JcaPGPSecretKeyRingCollection.java
//

#ifndef JcaPGPSecretKeyRingCollection_H
#define JcaPGPSecretKeyRingCollection_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPSecretKeyRingCollection.h"

@class IOSByteArray;
@class JavaIoInputStream;
@protocol JavaUtilCollection;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection : LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype __nonnull)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithByteArray_(LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *self, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithByteArray_(IOSByteArray *encoding);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *self, JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaUtilCollection_(LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *self, id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpJcajceJcaPGPSecretKeyRingCollection)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaPGPSecretKeyRingCollection_H
