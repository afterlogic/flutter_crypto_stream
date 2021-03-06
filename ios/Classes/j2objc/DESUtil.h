//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/DESUtil.java
//

#ifndef DESUtil_H
#define DESUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)isDESWithNSString:(NSString *)algorithmID;

+ (void)setOddParityWithByteArray:(IOSByteArray *)bytes;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_isDESWithNSString_(NSString *algorithmID);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil_setOddParityWithByteArray_(IOSByteArray *bytes);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilDESUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DESUtil_H
