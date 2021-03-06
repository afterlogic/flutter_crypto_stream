//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/PEMUtil.java
//

#ifndef PEMUtil_H
#define PEMUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoInputStream;
@class LibOrgBouncycastleAsn1ASN1Sequence;

@interface LibOrgBouncycastleJceProviderPEMUtil : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)initWithNSString:(NSString *)type;

- (LibOrgBouncycastleAsn1ASN1Sequence *)readPEMObjectWithJavaIoInputStream:(JavaIoInputStream *)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderPEMUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderPEMUtil_initWithNSString_(LibOrgBouncycastleJceProviderPEMUtil *self, NSString *type);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPEMUtil *new_LibOrgBouncycastleJceProviderPEMUtil_initWithNSString_(NSString *type) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderPEMUtil *create_LibOrgBouncycastleJceProviderPEMUtil_initWithNSString_(NSString *type);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderPEMUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PEMUtil_H
