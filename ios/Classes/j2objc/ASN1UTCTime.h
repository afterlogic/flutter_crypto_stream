//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1UTCTime.java
//

#ifndef ASN1UTCTime_H
#define ASN1UTCTime_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Primitive.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaUtilDate;
@class JavaUtilLocale;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1ASN1UTCTime : LibOrgBouncycastleAsn1ASN1Primitive

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilDate:(JavaUtilDate *)time;

- (instancetype __nonnull)initWithJavaUtilDate:(JavaUtilDate *)time
                            withJavaUtilLocale:(JavaUtilLocale *)locale;

- (instancetype __nonnull)initWithNSString:(NSString *)time;

- (JavaUtilDate *)getAdjustedDate;

- (NSString *)getAdjustedTime;

- (JavaUtilDate *)getDate;

+ (LibOrgBouncycastleAsn1ASN1UTCTime *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                 withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1ASN1UTCTime *)getInstanceWithId:(id)obj;

- (NSString *)getTime;

- (NSUInteger)hash;

- (NSString *)description;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)time;

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (jboolean)isConstructed;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1UTCTime)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *LibOrgBouncycastleAsn1ASN1UTCTime_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *LibOrgBouncycastleAsn1ASN1UTCTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1UTCTime_initWithNSString_(LibOrgBouncycastleAsn1ASN1UTCTime *self, NSString *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *new_LibOrgBouncycastleAsn1ASN1UTCTime_initWithNSString_(NSString *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *create_LibOrgBouncycastleAsn1ASN1UTCTime_initWithNSString_(NSString *time);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(LibOrgBouncycastleAsn1ASN1UTCTime *self, JavaUtilDate *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *new_LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(JavaUtilDate *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *create_LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_(JavaUtilDate *time);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(LibOrgBouncycastleAsn1ASN1UTCTime *self, JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *new_LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *create_LibOrgBouncycastleAsn1ASN1UTCTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1UTCTime_initWithByteArray_(LibOrgBouncycastleAsn1ASN1UTCTime *self, IOSByteArray *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *new_LibOrgBouncycastleAsn1ASN1UTCTime_initWithByteArray_(IOSByteArray *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1UTCTime *create_LibOrgBouncycastleAsn1ASN1UTCTime_initWithByteArray_(IOSByteArray *time);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1UTCTime)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1UTCTime_H
