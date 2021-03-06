//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/LocalizedMessage.java
//

#include "Filter.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "LocaleString.h"
#include "LocalizedMessage.h"
#include "MissingEntryException.h"
#include "TrustedInput.h"
#include "UntrustedInput.h"
#include "UntrustedUrlInput.h"
#include "java/io/UnsupportedEncodingException.h"
#include "java/lang/ClassLoader.h"
#include "java/lang/NullPointerException.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/StringBuffer.h"
#include "java/nio/charset/Charset.h"
#include "java/text/DateFormat.h"
#include "java/text/Format.h"
#include "java/text/MessageFormat.h"
#include "java/util/Locale.h"
#include "java/util/MissingResourceException.h"
#include "java/util/ResourceBundle.h"
#include "java/util/TimeZone.h"

@interface LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments ()

- (id)filterWithInt:(jint)type
             withId:(id)obj;

@end

__attribute__((unused)) static id LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_filterWithInt_withId_(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *self, jint type, id obj);

NSString *LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING = @"ISO-8859-1";

@implementation LibOrgBouncycastleI18nLocalizedMessage

+ (NSString *)DEFAULT_ENCODING {
  return LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_ {
  LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_(self, resource, id_);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding {
  LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_(self, resource, id_, encoding);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
               withNSObjectArray:(IOSObjectArray *)arguments {
  LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSObjectArray_(self, resource, id_, arguments);
  return self;
}

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding
               withNSObjectArray:(IOSObjectArray *)arguments {
  LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_withNSObjectArray_(self, resource, id_, encoding, arguments);
  return self;
}

- (NSString *)getEntryWithNSString:(NSString *)key
                withJavaUtilLocale:(JavaUtilLocale *)loc
              withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone {
  NSString *entry_ = id__;
  if (key != nil) {
    (void) JreStrAppendStrong(&entry_, "C$", '.', key);
  }
  @try {
    JavaUtilResourceBundle *bundle;
    if (loader_ == nil) {
      bundle = JavaUtilResourceBundle_getBundleWithNSString_withJavaUtilLocale_(resource_, loc);
    }
    else {
      bundle = JavaUtilResourceBundle_getBundleWithNSString_withJavaUtilLocale_withJavaLangClassLoader_(resource_, loc, loader_);
    }
    NSString *result = [((JavaUtilResourceBundle *) nil_chk(bundle)) getStringWithNSString:entry_];
    if (![((NSString *) nil_chk(encoding_)) isEqual:LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING]) {
      result = [NSString java_stringWithBytes:[((NSString *) nil_chk(result)) java_getBytesWithCharsetName:LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING] charsetName:encoding_];
    }
    if (![((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(arguments_)) isEmpty]) {
      result = [self formatWithTimeZoneWithNSString:result withNSObjectArray:[((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(arguments_)) getFilteredArgsWithJavaUtilLocale:loc] withJavaUtilLocale:loc withJavaUtilTimeZone:timezone];
    }
    result = [self addExtraArgsWithNSString:result withJavaUtilLocale:loc];
    return result;
  }
  @catch (JavaUtilMissingResourceException *mre) {
    @throw new_LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(JreStrcat("$$$$C", @"Can't find entry ", entry_, @" in resource file ", resource_, '.'), resource_, entry_, loc, loader_ != nil ? loader_ : [self getClassLoader]);
  }
  @catch (JavaIoUnsupportedEncodingException *use) {
    @throw new_JavaLangRuntimeException_initWithJavaLangThrowable_(use);
  }
}

- (NSString *)formatWithTimeZoneWithNSString:(NSString *)template_
                           withNSObjectArray:(IOSObjectArray *)arguments
                          withJavaUtilLocale:(JavaUtilLocale *)locale
                        withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone {
  JavaTextMessageFormat *mf = new_JavaTextMessageFormat_initWithNSString_(@" ");
  [mf setLocaleWithJavaUtilLocale:locale];
  [mf applyPatternWithNSString:template_];
  if (![((JavaUtilTimeZone *) nil_chk(timezone)) isEqual:JavaUtilTimeZone_getDefault()]) {
    IOSObjectArray *formats = [mf getFormats];
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(formats))->size_; i++) {
      if ([IOSObjectArray_Get(formats, i) isKindOfClass:[JavaTextDateFormat class]]) {
        JavaTextDateFormat *temp = (JavaTextDateFormat *) cast_chk(IOSObjectArray_Get(formats, i), [JavaTextDateFormat class]);
        [((JavaTextDateFormat *) nil_chk(temp)) setTimeZoneWithJavaUtilTimeZone:timezone];
        [mf setFormatWithInt:i withJavaTextFormat:temp];
      }
    }
  }
  return [mf formatWithId:arguments];
}

- (NSString *)addExtraArgsWithNSString:(NSString *)msg
                    withJavaUtilLocale:(JavaUtilLocale *)locale {
  if (extraArgs_ != nil) {
    JavaLangStringBuffer *sb = new_JavaLangStringBuffer_initWithNSString_(msg);
    IOSObjectArray *filteredArgs = [((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(extraArgs_)) getFilteredArgsWithJavaUtilLocale:locale];
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(filteredArgs))->size_; i++) {
      (void) [sb appendWithId:IOSObjectArray_Get(filteredArgs, i)];
    }
    msg = [sb description];
  }
  return msg;
}

- (void)setFilterWithLibOrgBouncycastleI18nFilterFilter:(id<LibOrgBouncycastleI18nFilterFilter>)filter {
  [((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(arguments_)) setFilterWithLibOrgBouncycastleI18nFilterFilter:filter];
  if (extraArgs_ != nil) {
    [extraArgs_ setFilterWithLibOrgBouncycastleI18nFilterFilter:filter];
  }
  self->filter_ = filter;
}

- (id<LibOrgBouncycastleI18nFilterFilter>)getFilter {
  return filter_;
}

- (void)setClassLoaderWithJavaLangClassLoader:(JavaLangClassLoader *)loader {
  self->loader_ = loader;
}

- (JavaLangClassLoader *)getClassLoader {
  return loader_;
}

- (NSString *)getId {
  return id__;
}

- (NSString *)getResource {
  return resource_;
}

- (IOSObjectArray *)getArguments {
  return [((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(arguments_)) getArguments];
}

- (void)setExtraArgumentWithId:(id)extraArg {
  [self setExtraArgumentsWithNSObjectArray:[IOSObjectArray newArrayWithObjects:(id[]){ extraArg } count:1 type:NSObject_class_()]];
}

- (void)setExtraArgumentsWithNSObjectArray:(IOSObjectArray *)extraArgs {
  if (extraArgs != nil) {
    self->extraArgs_ = new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(self, extraArgs);
    [self->extraArgs_ setFilterWithLibOrgBouncycastleI18nFilterFilter:filter_];
  }
  else {
    self->extraArgs_ = nil;
  }
}

- (IOSObjectArray *)getExtraArgs {
  return (extraArgs_ == nil) ? nil : [((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(extraArgs_)) getArguments];
}

- (NSString *)description {
  JavaLangStringBuffer *sb = new_JavaLangStringBuffer_init();
  (void) [((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@"Resource: \""])) appendWithNSString:resource_];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@"\" Id: \""])) appendWithNSString:id__])) appendWithNSString:@"\""];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@" Arguments: "])) appendWithInt:((IOSObjectArray *) nil_chk([((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(arguments_)) getArguments]))->size_])) appendWithNSString:@" normal"];
  if (extraArgs_ != nil && ((IOSObjectArray *) nil_chk([extraArgs_ getArguments]))->size_ > 0) {
    (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@", "])) appendWithInt:((IOSObjectArray *) nil_chk([((LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *) nil_chk(extraArgs_)) getArguments]))->size_])) appendWithNSString:@" extra"];
  }
  (void) [((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@" Encoding: "])) appendWithNSString:encoding_];
  (void) [((JavaLangStringBuffer *) nil_chk([sb appendWithNSString:@" ClassLoader: "])) appendWithId:loader_];
  return [sb description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, 9, 10, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 13, 14, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleI18nFilterFilter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 16, -1, -1, -1, -1 },
    { NULL, "LJavaLangClassLoader;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 18, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 19, 20, -1, -1, -1, -1 },
    { NULL, "[LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 21, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withNSString:);
  methods[1].selector = @selector(initWithNSString:withNSString:withNSString:);
  methods[2].selector = @selector(initWithNSString:withNSString:withNSObjectArray:);
  methods[3].selector = @selector(initWithNSString:withNSString:withNSString:withNSObjectArray:);
  methods[4].selector = @selector(getEntryWithNSString:withJavaUtilLocale:withJavaUtilTimeZone:);
  methods[5].selector = @selector(formatWithTimeZoneWithNSString:withNSObjectArray:withJavaUtilLocale:withJavaUtilTimeZone:);
  methods[6].selector = @selector(addExtraArgsWithNSString:withJavaUtilLocale:);
  methods[7].selector = @selector(setFilterWithLibOrgBouncycastleI18nFilterFilter:);
  methods[8].selector = @selector(getFilter);
  methods[9].selector = @selector(setClassLoaderWithJavaLangClassLoader:);
  methods[10].selector = @selector(getClassLoader);
  methods[11].selector = @selector(getId);
  methods[12].selector = @selector(getResource);
  methods[13].selector = @selector(getArguments);
  methods[14].selector = @selector(setExtraArgumentWithId:);
  methods[15].selector = @selector(setExtraArgumentsWithNSObjectArray:);
  methods[16].selector = @selector(getExtraArgs);
  methods[17].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "id__", "LNSString;", .constantValue.asLong = 0, 0x14, 22, -1, -1, -1 },
    { "resource_", "LNSString;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "DEFAULT_ENCODING", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 23, -1, -1 },
    { "encoding_", "LNSString;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "arguments_", "LLibOrgBouncycastleI18nLocalizedMessage_FilteredArguments;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "extraArgs_", "LLibOrgBouncycastleI18nLocalizedMessage_FilteredArguments;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "filter_", "LLibOrgBouncycastleI18nFilterFilter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "loader_", "LJavaLangClassLoader;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LNSString;", "LJavaLangNullPointerException;", "LNSString;LNSString;LNSString;", "LJavaLangNullPointerException;LJavaIoUnsupportedEncodingException;", "LNSString;LNSString;[LNSObject;", "LNSString;LNSString;LNSString;[LNSObject;", "getEntry", "LNSString;LJavaUtilLocale;LJavaUtilTimeZone;", "LLibOrgBouncycastleI18nMissingEntryException;", "formatWithTimeZone", "LNSString;[LNSObject;LJavaUtilLocale;LJavaUtilTimeZone;", "addExtraArgs", "LNSString;LJavaUtilLocale;", "setFilter", "LLibOrgBouncycastleI18nFilterFilter;", "setClassLoader", "LJavaLangClassLoader;", "setExtraArgument", "LNSObject;", "setExtraArguments", "[LNSObject;", "toString", "id", &LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING, "LLibOrgBouncycastleI18nLocalizedMessage_FilteredArguments;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleI18nLocalizedMessage = { "LocalizedMessage", "lib.org.bouncycastle.i18n", ptrTable, methods, fields, 7, 0x1, 18, 8, -1, 24, -1, -1, -1 };
  return &_LibOrgBouncycastleI18nLocalizedMessage;
}

@end

void LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_(LibOrgBouncycastleI18nLocalizedMessage *self, NSString *resource, NSString *id_) {
  NSObject_init(self);
  self->encoding_ = LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING;
  self->extraArgs_ = nil;
  self->filter_ = nil;
  self->loader_ = nil;
  if (resource == nil || id_ == nil) {
    @throw new_JavaLangNullPointerException_init();
  }
  self->id__ = id_;
  self->resource_ = resource;
  self->arguments_ = new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(self);
}

LibOrgBouncycastleI18nLocalizedMessage *new_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_(NSString *resource, NSString *id_) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_, resource, id_)
}

LibOrgBouncycastleI18nLocalizedMessage *create_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_(NSString *resource, NSString *id_) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_, resource, id_)
}

void LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleI18nLocalizedMessage *self, NSString *resource, NSString *id_, NSString *encoding) {
  NSObject_init(self);
  self->encoding_ = LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING;
  self->extraArgs_ = nil;
  self->filter_ = nil;
  self->loader_ = nil;
  if (resource == nil || id_ == nil) {
    @throw new_JavaLangNullPointerException_init();
  }
  self->id__ = id_;
  self->resource_ = resource;
  self->arguments_ = new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(self);
  if (!JavaNioCharsetCharset_isSupportedWithNSString_(encoding)) {
    @throw new_JavaIoUnsupportedEncodingException_initWithNSString_(JreStrcat("$$$", @"The encoding \"", encoding, @"\" is not supported."));
  }
  self->encoding_ = encoding;
}

LibOrgBouncycastleI18nLocalizedMessage *new_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSString_, resource, id_, encoding)
}

LibOrgBouncycastleI18nLocalizedMessage *create_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSString_, resource, id_, encoding)
}

void LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nLocalizedMessage *self, NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  NSObject_init(self);
  self->encoding_ = LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING;
  self->extraArgs_ = nil;
  self->filter_ = nil;
  self->loader_ = nil;
  if (resource == nil || id_ == nil || arguments == nil) {
    @throw new_JavaLangNullPointerException_init();
  }
  self->id__ = id_;
  self->resource_ = resource;
  self->arguments_ = new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(self, arguments);
}

LibOrgBouncycastleI18nLocalizedMessage *new_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSObjectArray_, resource, id_, arguments)
}

LibOrgBouncycastleI18nLocalizedMessage *create_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSObjectArray_, resource, id_, arguments)
}

void LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_withNSObjectArray_(LibOrgBouncycastleI18nLocalizedMessage *self, NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  NSObject_init(self);
  self->encoding_ = LibOrgBouncycastleI18nLocalizedMessage_DEFAULT_ENCODING;
  self->extraArgs_ = nil;
  self->filter_ = nil;
  self->loader_ = nil;
  if (resource == nil || id_ == nil || arguments == nil) {
    @throw new_JavaLangNullPointerException_init();
  }
  self->id__ = id_;
  self->resource_ = resource;
  self->arguments_ = new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(self, arguments);
  if (!JavaNioCharsetCharset_isSupportedWithNSString_(encoding)) {
    @throw new_JavaIoUnsupportedEncodingException_initWithNSString_(JreStrcat("$$$", @"The encoding \"", encoding, @"\" is not supported."));
  }
  self->encoding_ = encoding;
}

LibOrgBouncycastleI18nLocalizedMessage *new_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSString_withNSObjectArray_, resource, id_, encoding, arguments)
}

LibOrgBouncycastleI18nLocalizedMessage *create_LibOrgBouncycastleI18nLocalizedMessage_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage, initWithNSString_withNSString_withNSString_withNSObjectArray_, resource, id_, encoding, arguments)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleI18nLocalizedMessage)

@implementation LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments

+ (jint)NO_FILTER {
  return LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_NO_FILTER;
}

+ (jint)FILTER {
  return LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER;
}

+ (jint)FILTER_URL {
  return LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER_URL;
}

- (instancetype)initWithLibOrgBouncycastleI18nLocalizedMessage:(LibOrgBouncycastleI18nLocalizedMessage *)outer$ {
  LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(self, outer$);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleI18nLocalizedMessage:(LibOrgBouncycastleI18nLocalizedMessage *)outer$
                                             withNSObjectArray:(IOSObjectArray *)args {
  LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(self, outer$, args);
  return self;
}

- (jboolean)isEmpty {
  return ((IOSObjectArray *) nil_chk(unpackedArgs_))->size_ == 0;
}

- (IOSObjectArray *)getArguments {
  return arguments_;
}

- (IOSObjectArray *)getFilteredArgsWithJavaUtilLocale:(JavaUtilLocale *)locale {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(unpackedArgs_))->size_ type:NSObject_class_()];
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(unpackedArgs_))->size_; i++) {
    id arg;
    if (IOSObjectArray_Get(nil_chk(filteredArgs_), i) != nil) {
      arg = IOSObjectArray_Get(filteredArgs_, i);
    }
    else {
      arg = IOSObjectArray_Get(unpackedArgs_, i);
      if (IOSBooleanArray_Get(nil_chk(isLocaleSpecific_), i)) {
        arg = [((LibOrgBouncycastleI18nLocaleString *) nil_chk(((LibOrgBouncycastleI18nLocaleString *) cast_chk(arg, [LibOrgBouncycastleI18nLocaleString class])))) getLocaleStringWithJavaUtilLocale:locale];
        arg = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_filterWithInt_withId_(self, IOSIntArray_Get(nil_chk(argFilterType_), i), arg);
      }
      else {
        arg = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_filterWithInt_withId_(self, IOSIntArray_Get(nil_chk(argFilterType_), i), arg);
        (void) IOSObjectArray_Set(nil_chk(filteredArgs_), i, arg);
      }
    }
    (void) IOSObjectArray_Set(result, i, arg);
  }
  return result;
}

- (id)filterWithInt:(jint)type
             withId:(id)obj {
  return LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_filterWithInt_withId_(self, type, obj);
}

- (id<LibOrgBouncycastleI18nFilterFilter>)getFilter {
  return filter_;
}

- (void)setFilterWithLibOrgBouncycastleI18nFilterFilter:(id<LibOrgBouncycastleI18nFilterFilter>)filter {
  if (filter != self->filter_) {
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(unpackedArgs_))->size_; i++) {
      (void) IOSObjectArray_Set(nil_chk(filteredArgs_), i, nil);
    }
  }
  self->filter_ = filter;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LNSObject;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleI18nFilterFilter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleI18nLocalizedMessage:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleI18nLocalizedMessage:withNSObjectArray:);
  methods[2].selector = @selector(isEmpty);
  methods[3].selector = @selector(getArguments);
  methods[4].selector = @selector(getFilteredArgsWithJavaUtilLocale:);
  methods[5].selector = @selector(filterWithInt:withId:);
  methods[6].selector = @selector(getFilter);
  methods[7].selector = @selector(setFilterWithLibOrgBouncycastleI18nFilterFilter:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "NO_FILTER", "I", .constantValue.asInt = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_NO_FILTER, 0x1c, -1, -1, -1, -1 },
    { "FILTER", "I", .constantValue.asInt = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER, 0x1c, -1, -1, -1, -1 },
    { "FILTER_URL", "I", .constantValue.asInt = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER_URL, 0x1c, -1, -1, -1, -1 },
    { "filter_", "LLibOrgBouncycastleI18nFilterFilter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "isLocaleSpecific_", "[Z", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "argFilterType_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "arguments_", "[LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "unpackedArgs_", "[LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "filteredArgs_", "[LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[LNSObject;", "getFilteredArgs", "LJavaUtilLocale;", "filter", "ILNSObject;", "setFilter", "LLibOrgBouncycastleI18nFilterFilter;", "LLibOrgBouncycastleI18nLocalizedMessage;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments = { "FilteredArguments", "lib.org.bouncycastle.i18n", ptrTable, methods, fields, 7, 0x4, 8, 9, 7, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments;
}

@end

void LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *self, LibOrgBouncycastleI18nLocalizedMessage *outer$) {
  LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(self, outer$, [IOSObjectArray newArrayWithLength:0 type:NSObject_class_()]);
}

LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(LibOrgBouncycastleI18nLocalizedMessage *outer$) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments, initWithLibOrgBouncycastleI18nLocalizedMessage_, outer$)
}

LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *create_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_(LibOrgBouncycastleI18nLocalizedMessage *outer$) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments, initWithLibOrgBouncycastleI18nLocalizedMessage_, outer$)
}

void LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *self, LibOrgBouncycastleI18nLocalizedMessage *outer$, IOSObjectArray *args) {
  NSObject_init(self);
  self->filter_ = nil;
  self->arguments_ = args;
  self->unpackedArgs_ = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(args))->size_ type:NSObject_class_()];
  self->filteredArgs_ = [IOSObjectArray newArrayWithLength:args->size_ type:NSObject_class_()];
  self->isLocaleSpecific_ = [IOSBooleanArray newArrayWithLength:args->size_];
  self->argFilterType_ = [IOSIntArray newArrayWithLength:args->size_];
  for (jint i = 0; i < args->size_; i++) {
    if ([IOSObjectArray_Get(args, i) isKindOfClass:[LibOrgBouncycastleI18nFilterTrustedInput class]]) {
      (void) IOSObjectArray_Set(self->unpackedArgs_, i, [((LibOrgBouncycastleI18nFilterTrustedInput *) nil_chk(((LibOrgBouncycastleI18nFilterTrustedInput *) cast_chk(IOSObjectArray_Get(args, i), [LibOrgBouncycastleI18nFilterTrustedInput class])))) getInput]);
      *IOSIntArray_GetRef(nil_chk(self->argFilterType_), i) = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_NO_FILTER;
    }
    else if ([IOSObjectArray_Get(args, i) isKindOfClass:[LibOrgBouncycastleI18nFilterUntrustedInput class]]) {
      (void) IOSObjectArray_Set(self->unpackedArgs_, i, [((LibOrgBouncycastleI18nFilterUntrustedInput *) nil_chk(((LibOrgBouncycastleI18nFilterUntrustedInput *) cast_chk(IOSObjectArray_Get(args, i), [LibOrgBouncycastleI18nFilterUntrustedInput class])))) getInput]);
      if ([IOSObjectArray_Get(args, i) isKindOfClass:[LibOrgBouncycastleI18nFilterUntrustedUrlInput class]]) {
        *IOSIntArray_GetRef(nil_chk(self->argFilterType_), i) = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER_URL;
      }
      else {
        *IOSIntArray_GetRef(nil_chk(self->argFilterType_), i) = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER;
      }
    }
    else {
      (void) IOSObjectArray_Set(self->unpackedArgs_, i, IOSObjectArray_Get(args, i));
      *IOSIntArray_GetRef(self->argFilterType_, i) = LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER;
    }
    *IOSBooleanArray_GetRef(nil_chk(self->isLocaleSpecific_), i) = ([IOSObjectArray_Get(nil_chk(self->unpackedArgs_), i) isKindOfClass:[LibOrgBouncycastleI18nLocaleString class]]);
  }
}

LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *new_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(LibOrgBouncycastleI18nLocalizedMessage *outer$, IOSObjectArray *args) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments, initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_, outer$, args)
}

LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *create_LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_(LibOrgBouncycastleI18nLocalizedMessage *outer$, IOSObjectArray *args) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments, initWithLibOrgBouncycastleI18nLocalizedMessage_withNSObjectArray_, outer$, args)
}

id LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_filterWithInt_withId_(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments *self, jint type, id obj) {
  if (self->filter_ != nil) {
    id o = (nil == obj) ? @"null" : obj;
    switch (type) {
      case LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_NO_FILTER:
      return o;
      case LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER:
      return [self->filter_ doFilterWithNSString:[o description]];
      case LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments_FILTER_URL:
      return [self->filter_ doFilterUrlWithNSString:[o description]];
      default:
      return nil;
    }
  }
  else {
    return obj;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleI18nLocalizedMessage_FilteredArguments)
