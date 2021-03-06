//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1GeneralizedTime.java
//

#ifndef ASN1GeneralizedTime_H
#define ASN1GeneralizedTime_H

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

@interface LibOrgBouncycastleAsn1ASN1GeneralizedTime : LibOrgBouncycastleAsn1ASN1Primitive {
 @public
  IOSByteArray *time_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilDate:(JavaUtilDate *)time;

- (instancetype __nonnull)initWithJavaUtilDate:(JavaUtilDate *)time
                            withJavaUtilLocale:(JavaUtilLocale *)locale;

- (instancetype __nonnull)initWithNSString:(NSString *)time;

- (JavaUtilDate *)getDate;

+ (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                         withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getInstanceWithId:(id)obj;

- (NSString *)getTime;

- (NSString *)getTimeString;

- (NSUInteger)hash;

#pragma mark Protected

- (jboolean)hasFractionalSeconds;

- (jboolean)hasMinutes;

- (jboolean)hasSeconds;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)bytes;

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (jboolean)isConstructed;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1GeneralizedTime)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1GeneralizedTime, time_, IOSByteArray *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, NSString *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1GeneralizedTime)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1GeneralizedTime_H
