//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/SkeinParameterSpec.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "SkeinParameterSpec.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/io/OutputStreamWriter.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Integer.h"
#include "java/text/DateFormat.h"
#include "java/text/SimpleDateFormat.h"
#include "java/util/Collections.h"
#include "java/util/Date.h"
#include "java/util/HashMap.h"
#include "java/util/Iterator.h"
#include "java/util/Locale.h"
#include "java/util/Map.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleJcajceSpecSkeinParameterSpec () {
 @public
  id<JavaUtilMap> parameters_;
}

- (instancetype)initWithJavaUtilMap:(id<JavaUtilMap>)parameters;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecSkeinParameterSpec, parameters_, id<JavaUtilMap>)

__attribute__((unused)) static void LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *self, id<JavaUtilMap> parameters);

__attribute__((unused)) static LibOrgBouncycastleJcajceSpecSkeinParameterSpec *new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(id<JavaUtilMap> parameters) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceSpecSkeinParameterSpec *create_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(id<JavaUtilMap> parameters);

@interface LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder () {
 @public
  id<JavaUtilMap> parameters_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder, parameters_, id<JavaUtilMap>)

@implementation LibOrgBouncycastleJcajceSpecSkeinParameterSpec

+ (jint)PARAM_TYPE_KEY {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY;
}

+ (jint)PARAM_TYPE_CONFIG {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_CONFIG;
}

+ (jint)PARAM_TYPE_PERSONALISATION {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION;
}

+ (jint)PARAM_TYPE_PUBLIC_KEY {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PUBLIC_KEY;
}

+ (jint)PARAM_TYPE_KEY_IDENTIFIER {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY_IDENTIFIER;
}

+ (jint)PARAM_TYPE_NONCE {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_NONCE;
}

+ (jint)PARAM_TYPE_MESSAGE {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_MESSAGE;
}

+ (jint)PARAM_TYPE_OUTPUT {
  return LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_OUTPUT;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceSpecSkeinParameterSpec_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithJavaUtilMap:(id<JavaUtilMap>)parameters {
  LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(self, parameters);
  return self;
}

- (id<JavaUtilMap>)getParameters {
  return parameters_;
}

- (IOSByteArray *)getKey {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_((IOSByteArray *) cast_chk([((id<JavaUtilMap>) nil_chk(parameters_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY)], [IOSByteArray class]));
}

- (IOSByteArray *)getPersonalisation {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_((IOSByteArray *) cast_chk([((id<JavaUtilMap>) nil_chk(parameters_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION)], [IOSByteArray class]));
}

- (IOSByteArray *)getPublicKey {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_((IOSByteArray *) cast_chk([((id<JavaUtilMap>) nil_chk(parameters_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PUBLIC_KEY)], [IOSByteArray class]));
}

- (IOSByteArray *)getKeyIdentifier {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_((IOSByteArray *) cast_chk([((id<JavaUtilMap>) nil_chk(parameters_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY_IDENTIFIER)], [IOSByteArray class]));
}

- (IOSByteArray *)getNonce {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_((IOSByteArray *) cast_chk([((id<JavaUtilMap>) nil_chk(parameters_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_NONCE)], [IOSByteArray class]));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilMap;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithJavaUtilMap:);
  methods[2].selector = @selector(getParameters);
  methods[3].selector = @selector(getKey);
  methods[4].selector = @selector(getPersonalisation);
  methods[5].selector = @selector(getPublicKey);
  methods[6].selector = @selector(getKeyIdentifier);
  methods[7].selector = @selector(getNonce);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PARAM_TYPE_KEY", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_CONFIG", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_CONFIG, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_PERSONALISATION", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_PUBLIC_KEY", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PUBLIC_KEY, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_KEY_IDENTIFIER", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY_IDENTIFIER, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_NONCE", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_NONCE, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_MESSAGE", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_MESSAGE, 0x19, -1, -1, -1, -1 },
    { "PARAM_TYPE_OUTPUT", "I", .constantValue.asInt = LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_OUTPUT, 0x19, -1, -1, -1, -1 },
    { "parameters_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilMap;", "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecSkeinParameterSpec = { "SkeinParameterSpec", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 8, 9, -1, 1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecSkeinParameterSpec;
}

@end

void LibOrgBouncycastleJcajceSpecSkeinParameterSpec_init(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *self) {
  LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(self, new_JavaUtilHashMap_init());
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec *new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec, init)
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec *create_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec, init)
}

void LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *self, id<JavaUtilMap> parameters) {
  NSObject_init(self);
  self->parameters_ = JavaUtilCollections_unmodifiableMapWithJavaUtilMap_(parameters);
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec *new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(id<JavaUtilMap> parameters) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec, initWithJavaUtilMap_, parameters)
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec *create_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(id<JavaUtilMap> parameters) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec, initWithJavaUtilMap_, parameters)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecSkeinParameterSpec)

@implementation LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec:(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *)params {
  LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_(self, params);
  return self;
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setWithInt:(jint)type
                                                         withByteArray:(IOSByteArray *)value {
  if (value == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Parameter value must not be null.");
  }
  if ((type != LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY) && (type <= LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_CONFIG || type >= LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_OUTPUT || type == LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_MESSAGE)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Parameter types must be in the range 0,5..47,49..62.");
  }
  if (type == LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_CONFIG) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$", @"Parameter type ", LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_CONFIG, @" is reserved for internal use."));
  }
  (void) [((id<JavaUtilMap>) nil_chk(self->parameters_)) putWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(type) withId:value];
  return self;
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setKeyWithByteArray:(IOSByteArray *)key {
  return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY withByteArray:key];
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setPersonalisationWithByteArray:(IOSByteArray *)personalisation {
  return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION withByteArray:personalisation];
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setPersonalisationWithJavaUtilDate:(JavaUtilDate *)date
                                                                                  withNSString:(NSString *)emailAddress
                                                                                  withNSString:(NSString *)distinguisher {
  @try {
    JavaIoByteArrayOutputStream *bout = new_JavaIoByteArrayOutputStream_init();
    JavaIoOutputStreamWriter *out = new_JavaIoOutputStreamWriter_initWithJavaIoOutputStream_withNSString_(bout, @"UTF-8");
    JavaTextDateFormat *format = new_JavaTextSimpleDateFormat_initWithNSString_(@"YYYYMMDD");
    [out writeWithNSString:[format formatWithJavaUtilDate:date]];
    [out writeWithNSString:@" "];
    [out writeWithNSString:emailAddress];
    [out writeWithNSString:@" "];
    [out writeWithNSString:distinguisher];
    [out close];
    return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION withByteArray:[bout toByteArray]];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$@", @"Byte I/O failed: ", e));
  }
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setPersonalisationWithJavaUtilDate:(JavaUtilDate *)date
                                                                            withJavaUtilLocale:(JavaUtilLocale *)dateLocale
                                                                                  withNSString:(NSString *)emailAddress
                                                                                  withNSString:(NSString *)distinguisher {
  @try {
    JavaIoByteArrayOutputStream *bout = new_JavaIoByteArrayOutputStream_init();
    JavaIoOutputStreamWriter *out = new_JavaIoOutputStreamWriter_initWithJavaIoOutputStream_withNSString_(bout, @"UTF-8");
    JavaTextDateFormat *format = new_JavaTextSimpleDateFormat_initWithNSString_withJavaUtilLocale_(@"YYYYMMDD", dateLocale);
    [out writeWithNSString:[format formatWithJavaUtilDate:date]];
    [out writeWithNSString:@" "];
    [out writeWithNSString:emailAddress];
    [out writeWithNSString:@" "];
    [out writeWithNSString:distinguisher];
    [out close];
    return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PERSONALISATION withByteArray:[bout toByteArray]];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$@", @"Byte I/O failed: ", e));
  }
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setPublicKeyWithByteArray:(IOSByteArray *)publicKey {
  return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_PUBLIC_KEY withByteArray:publicKey];
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setKeyIdentifierWithByteArray:(IOSByteArray *)keyIdentifier {
  return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_KEY_IDENTIFIER withByteArray:keyIdentifier];
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *)setNonceWithByteArray:(IOSByteArray *)nonce {
  return [self setWithInt:LibOrgBouncycastleJcajceSpecSkeinParameterSpec_PARAM_TYPE_NONCE withByteArray:nonce];
}

- (LibOrgBouncycastleJcajceSpecSkeinParameterSpec *)build {
  return new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_initWithJavaUtilMap_(parameters_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 5, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 8, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 9, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;", 0x1, 10, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec:);
  methods[2].selector = @selector(setWithInt:withByteArray:);
  methods[3].selector = @selector(setKeyWithByteArray:);
  methods[4].selector = @selector(setPersonalisationWithByteArray:);
  methods[5].selector = @selector(setPersonalisationWithJavaUtilDate:withNSString:withNSString:);
  methods[6].selector = @selector(setPersonalisationWithJavaUtilDate:withJavaUtilLocale:withNSString:withNSString:);
  methods[7].selector = @selector(setPublicKeyWithByteArray:);
  methods[8].selector = @selector(setKeyIdentifierWithByteArray:);
  methods[9].selector = @selector(setNonceWithByteArray:);
  methods[10].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "parameters_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceSpecSkeinParameterSpec;", "set", "I[B", "setKey", "[B", "setPersonalisation", "LJavaUtilDate;LNSString;LNSString;", "LJavaUtilDate;LJavaUtilLocale;LNSString;LNSString;", "setPublicKey", "setKeyIdentifier", "setNonce" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder = { "Builder", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x9, 11, 1, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder;
}

@end

void LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_init(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *self) {
  NSObject_init(self);
  self->parameters_ = new_JavaUtilHashMap_init();
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder, init)
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *create_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder, init)
}

void LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *self, LibOrgBouncycastleJcajceSpecSkeinParameterSpec *params) {
  NSObject_init(self);
  self->parameters_ = new_JavaUtilHashMap_init();
  id<JavaUtilIterator> keys = [((id<JavaUtilSet>) nil_chk([((id<JavaUtilMap>) nil_chk(((LibOrgBouncycastleJcajceSpecSkeinParameterSpec *) nil_chk(params))->parameters_)) keySet])) iterator];
  while ([((id<JavaUtilIterator>) nil_chk(keys)) hasNext]) {
    JavaLangInteger *key = (JavaLangInteger *) cast_chk([keys next], [JavaLangInteger class]);
    (void) [((id<JavaUtilMap>) nil_chk(self->parameters_)) putWithId:key withId:[((id<JavaUtilMap>) nil_chk(params->parameters_)) getWithId:key]];
  }
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *new_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder, initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_, params)
}

LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder *create_LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder_initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_(LibOrgBouncycastleJcajceSpecSkeinParameterSpec *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder, initWithLibOrgBouncycastleJcajceSpecSkeinParameterSpec_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecSkeinParameterSpec_Builder)
