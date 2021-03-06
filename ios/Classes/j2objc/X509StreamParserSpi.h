//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509StreamParserSpi.java
//

#ifndef X509StreamParserSpi_H
#define X509StreamParserSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoInputStream;
@protocol JavaUtilCollection;

@interface LibOrgBouncycastleX509X509StreamParserSpi : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (void)engineInitWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (id)engineRead;

- (id<JavaUtilCollection>)engineReadAll;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509StreamParserSpi)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509StreamParserSpi_init(LibOrgBouncycastleX509X509StreamParserSpi *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509StreamParserSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509StreamParserSpi_H
