//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509StreamParser.java
//

#ifndef X509StreamParser_H
#define X509StreamParser_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "X509UtilX509StreamParser.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaSecurityProvider;
@protocol JavaUtilCollection;

@interface LibOrgBouncycastleX509X509StreamParser : NSObject < LibOrgBouncycastleX509UtilX509UtilX509StreamParser >

#pragma mark Public

+ (LibOrgBouncycastleX509X509StreamParser *)getInstanceWithNSString:(NSString *)type;

+ (LibOrgBouncycastleX509X509StreamParser *)getInstanceWithNSString:(NSString *)type
                                           withJavaSecurityProvider:(JavaSecurityProvider *)provider;

+ (LibOrgBouncycastleX509X509StreamParser *)getInstanceWithNSString:(NSString *)type
                                                       withNSString:(NSString *)provider;

- (JavaSecurityProvider *)getProvider;

- (void)init__WithByteArray:(IOSByteArray *)data OBJC_METHOD_FAMILY_NONE;

- (void)init__WithJavaIoInputStream:(JavaIoInputStream *)stream OBJC_METHOD_FAMILY_NONE;

- (id)read;

- (id<JavaUtilCollection>)readAll;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509StreamParser)

FOUNDATION_EXPORT LibOrgBouncycastleX509X509StreamParser *LibOrgBouncycastleX509X509StreamParser_getInstanceWithNSString_(NSString *type);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509StreamParser *LibOrgBouncycastleX509X509StreamParser_getInstanceWithNSString_withNSString_(NSString *type, NSString *provider);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509StreamParser *LibOrgBouncycastleX509X509StreamParser_getInstanceWithNSString_withJavaSecurityProvider_(NSString *type, JavaSecurityProvider *provider);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509StreamParser)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509StreamParser_H
