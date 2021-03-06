//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/MessageBundle.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "MessageBundle.h"
#include "TextBundle.h"
#include "java/util/Locale.h"
#include "java/util/TimeZone.h"

NSString *LibOrgBouncycastleI18nMessageBundle_TITLE_ENTRY = @"title";

@implementation LibOrgBouncycastleI18nMessageBundle

+ (NSString *)TITLE_ENTRY {
  return LibOrgBouncycastleI18nMessageBundle_TITLE_ENTRY;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_ {
  LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_(self, resource, id_);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding {
  LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_(self, resource, id_, encoding);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
               withNSObjectArray:(IOSObjectArray *)arguments {
  LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSObjectArray_(self, resource, id_, arguments);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding
               withNSObjectArray:(IOSObjectArray *)arguments {
  LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(self, resource, id_, encoding, arguments);
  return self;
}

- (NSString *)getTitleWithJavaUtilLocale:(JavaUtilLocale *)loc
                    withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone {
  return [self getEntryWithNSString:LibOrgBouncycastleI18nMessageBundle_TITLE_ENTRY withJavaUtilLocale:loc withJavaUtilTimeZone:timezone];
}

- (NSString *)getTitleWithJavaUtilLocale:(JavaUtilLocale *)loc {
  return [self getEntryWithNSString:LibOrgBouncycastleI18nMessageBundle_TITLE_ENTRY withJavaUtilLocale:loc withJavaUtilTimeZone:JavaUtilTimeZone_getDefault()];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 6, 9, 8, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withNSString:);
  methods[1].selector = @selector(initWithNSString:withNSString:withNSString:);
  methods[2].selector = @selector(initWithNSString:withNSString:withNSObjectArray:);
  methods[3].selector = @selector(initWithNSString:withNSString:withNSString:withNSObjectArray:);
  methods[4].selector = @selector(getTitleWithJavaUtilLocale:withJavaUtilTimeZone:);
  methods[5].selector = @selector(getTitleWithJavaUtilLocale:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TITLE_ENTRY", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LNSString;", "LJavaLangNullPointerException;", "LNSString;LNSString;LNSString;", "LJavaLangNullPointerException;LJavaIoUnsupportedEncodingException;", "LNSString;LNSString;[LNSObject;", "LNSString;LNSString;LNSString;[LNSObject;", "getTitle", "LJavaUtilLocale;LJavaUtilTimeZone;", "LLibOrgBouncycastleI18nMissingEntryException;", "LJavaUtilLocale;", &LibOrgBouncycastleI18nMessageBundle_TITLE_ENTRY };
  static const J2ObjcClassInfo _LibOrgBouncycastleI18nMessageBundle = { "MessageBundle", "lib.org.bouncycastle.i18n", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleI18nMessageBundle;
}

@end

void LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_(LibOrgBouncycastleI18nMessageBundle *self, NSString *resource, NSString *id_) {
  LibOrgBouncycastleI18nTextBundle_initWithNSString_withNSString_(self, resource, id_);
}

LibOrgBouncycastleI18nMessageBundle *new_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_, resource, id_)
}

LibOrgBouncycastleI18nMessageBundle *create_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_, resource, id_)
}

void LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleI18nMessageBundle *self, NSString *resource, NSString *id_, NSString *encoding) {
  LibOrgBouncycastleI18nTextBundle_initWithNSString_withNSString_withNSString_(self, resource, id_, encoding);
}

LibOrgBouncycastleI18nMessageBundle *new_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSString_, resource, id_, encoding)
}

LibOrgBouncycastleI18nMessageBundle *create_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSString_, resource, id_, encoding)
}

void LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nMessageBundle *self, NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  LibOrgBouncycastleI18nTextBundle_initWithNSString_withNSString_withNSObjectArray_(self, resource, id_, arguments);
}

LibOrgBouncycastleI18nMessageBundle *new_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSObjectArray_, resource, id_, arguments)
}

LibOrgBouncycastleI18nMessageBundle *create_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSObjectArray_, resource, id_, arguments)
}

void LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nMessageBundle *self, NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  LibOrgBouncycastleI18nTextBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(self, resource, id_, encoding, arguments);
}

LibOrgBouncycastleI18nMessageBundle *new_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSString_withNSObjectArray_, resource, id_, encoding, arguments)
}

LibOrgBouncycastleI18nMessageBundle *create_LibOrgBouncycastleI18nMessageBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nMessageBundle, initWithNSString_withNSString_withNSString_withNSObjectArray_, resource, id_, encoding, arguments)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleI18nMessageBundle)
