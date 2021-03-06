//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/ErrorBundle.java
//

#ifndef ErrorBundle_H
#define ErrorBundle_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "MessageBundle.h"

@class IOSObjectArray;
@class JavaUtilLocale;
@class JavaUtilTimeZone;

@interface LibOrgBouncycastleI18nErrorBundle : LibOrgBouncycastleI18nMessageBundle
@property (readonly, copy, class) NSString *SUMMARY_ENTRY NS_SWIFT_NAME(SUMMARY_ENTRY);
@property (readonly, copy, class) NSString *DETAIL_ENTRY NS_SWIFT_NAME(DETAIL_ENTRY);

+ (NSString *)SUMMARY_ENTRY;

+ (NSString *)DETAIL_ENTRY;

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)resource
                              withNSString:(NSString *)id_;

- (instancetype __nonnull)initWithNSString:(NSString *)resource
                              withNSString:(NSString *)id_
                         withNSObjectArray:(IOSObjectArray *)arguments;

- (instancetype __nonnull)initWithNSString:(NSString *)resource
                              withNSString:(NSString *)id_
                              withNSString:(NSString *)encoding;

- (instancetype __nonnull)initWithNSString:(NSString *)resource
                              withNSString:(NSString *)id_
                              withNSString:(NSString *)encoding
                         withNSObjectArray:(IOSObjectArray *)arguments;

- (NSString *)getDetailWithJavaUtilLocale:(JavaUtilLocale *)loc;

- (NSString *)getDetailWithJavaUtilLocale:(JavaUtilLocale *)loc
                     withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone;

- (NSString *)getSummaryWithJavaUtilLocale:(JavaUtilLocale *)loc;

- (NSString *)getSummaryWithJavaUtilLocale:(JavaUtilLocale *)loc
                      withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleI18nErrorBundle)

inline NSString *LibOrgBouncycastleI18nErrorBundle_get_SUMMARY_ENTRY(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleI18nErrorBundle_SUMMARY_ENTRY;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleI18nErrorBundle, SUMMARY_ENTRY, NSString *)

inline NSString *LibOrgBouncycastleI18nErrorBundle_get_DETAIL_ENTRY(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleI18nErrorBundle_DETAIL_ENTRY;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleI18nErrorBundle, DETAIL_ENTRY, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_(LibOrgBouncycastleI18nErrorBundle *self, NSString *resource, NSString *id_);

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *new_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *create_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_);

FOUNDATION_EXPORT void LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleI18nErrorBundle *self, NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *new_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *create_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT void LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nErrorBundle *self, NSString *resource, NSString *id_, IOSObjectArray *arguments);

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *new_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *create_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments);

FOUNDATION_EXPORT void LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nErrorBundle *self, NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *new_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nErrorBundle *create_LibOrgBouncycastleI18nErrorBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleI18nErrorBundle)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ErrorBundle_H
