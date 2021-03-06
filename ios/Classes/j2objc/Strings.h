//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Strings.java
//

#ifndef Strings_H
#define Strings_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSCharArray;
@class IOSObjectArray;
@class JavaIoOutputStream;
@protocol LibOrgBouncycastleUtilStringList;

@interface LibOrgBouncycastleUtilStrings : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSCharArray *)asCharArrayWithByteArray:(IOSByteArray *)bytes;

+ (NSString *)fromByteArrayWithByteArray:(IOSByteArray *)bytes;

+ (NSString *)fromUTF8ByteArrayWithByteArray:(IOSByteArray *)bytes;

+ (NSString *)lineSeparator;

+ (id<LibOrgBouncycastleUtilStringList>)newList OBJC_METHOD_FAMILY_NONE;

+ (IOSObjectArray *)splitWithNSString:(NSString *)input
                             withChar:(jchar)delimiter;

+ (IOSByteArray *)toByteArrayWithCharArray:(IOSCharArray *)chars;

+ (IOSByteArray *)toByteArrayWithNSString:(NSString *)string;

+ (jint)toByteArrayWithNSString:(NSString *)s
                  withByteArray:(IOSByteArray *)buf
                        withInt:(jint)off;

+ (NSString *)toLowerCaseWithNSString:(NSString *)string;

+ (NSString *)toUpperCaseWithNSString:(NSString *)string;

+ (IOSByteArray *)toUTF8ByteArrayWithCharArray:(IOSCharArray *)string;

+ (void)toUTF8ByteArrayWithCharArray:(IOSCharArray *)string
              withJavaIoOutputStream:(JavaIoOutputStream *)sOut;

+ (IOSByteArray *)toUTF8ByteArrayWithNSString:(NSString *)string;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleUtilStrings)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilStrings_init(LibOrgBouncycastleUtilStrings *self);

FOUNDATION_EXPORT LibOrgBouncycastleUtilStrings *new_LibOrgBouncycastleUtilStrings_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilStrings *create_LibOrgBouncycastleUtilStrings_init(void);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilStrings_fromUTF8ByteArrayWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithNSString_(NSString *string);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithCharArray_(IOSCharArray *string);

FOUNDATION_EXPORT void LibOrgBouncycastleUtilStrings_toUTF8ByteArrayWithCharArray_withJavaIoOutputStream_(IOSCharArray *string, JavaIoOutputStream *sOut);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilStrings_toUpperCaseWithNSString_(NSString *string);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_(NSString *string);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleUtilStrings_toByteArrayWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleUtilStrings_toByteArrayWithNSString_(NSString *string);

FOUNDATION_EXPORT jint LibOrgBouncycastleUtilStrings_toByteArrayWithNSString_withByteArray_withInt_(NSString *s, IOSByteArray *buf, jint off);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilStrings_fromByteArrayWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSCharArray *LibOrgBouncycastleUtilStrings_asCharArrayWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleUtilStrings_splitWithNSString_withChar_(NSString *input, jchar delimiter);

FOUNDATION_EXPORT id<LibOrgBouncycastleUtilStringList> LibOrgBouncycastleUtilStrings_newList(void);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleUtilStrings_lineSeparator(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilStrings)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Strings_H
