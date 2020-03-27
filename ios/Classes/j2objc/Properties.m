//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Properties.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "Properties.h"
#include "Strings.h"
#include "java/lang/System.h"
#include "java/lang/ThreadLocal.h"
#include "java/math/BigInteger.h"
#include "java/security/AccessControlException.h"
#include "java/security/AccessController.h"
#include "java/security/PrivilegedAction.h"
#include "java/util/Collections.h"
#include "java/util/HashMap.h"
#include "java/util/HashSet.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "java/util/StringTokenizer.h"

@interface LibOrgBouncycastleUtilProperties ()

- (instancetype)init;

+ (NSString *)fetchPropertyWithNSString:(NSString *)propertyName;

@end

inline JavaLangThreadLocal *LibOrgBouncycastleUtilProperties_get_threadProperties(void);
static JavaLangThreadLocal *LibOrgBouncycastleUtilProperties_threadProperties;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleUtilProperties, threadProperties, JavaLangThreadLocal *)

__attribute__((unused)) static void LibOrgBouncycastleUtilProperties_init(LibOrgBouncycastleUtilProperties *self);

__attribute__((unused)) static LibOrgBouncycastleUtilProperties *new_LibOrgBouncycastleUtilProperties_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleUtilProperties *create_LibOrgBouncycastleUtilProperties_init(void);

__attribute__((unused)) static NSString *LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(NSString *propertyName);

@interface LibOrgBouncycastleUtilProperties_1 : NSObject < JavaSecurityPrivilegedAction > {
 @public
  NSString *val$propertyName_;
}

- (instancetype)initWithNSString:(NSString *)capture$0;

- (id)run;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilProperties_1)

__attribute__((unused)) static void LibOrgBouncycastleUtilProperties_1_initWithNSString_(LibOrgBouncycastleUtilProperties_1 *self, NSString *capture$0);

__attribute__((unused)) static LibOrgBouncycastleUtilProperties_1 *new_LibOrgBouncycastleUtilProperties_1_initWithNSString_(NSString *capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleUtilProperties_1 *create_LibOrgBouncycastleUtilProperties_1_initWithNSString_(NSString *capture$0);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleUtilProperties)

@implementation LibOrgBouncycastleUtilProperties

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilProperties_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isOverrideSetWithNSString:(NSString *)propertyName {
  return LibOrgBouncycastleUtilProperties_isOverrideSetWithNSString_(propertyName);
}

+ (jboolean)setThreadOverrideWithNSString:(NSString *)propertyName
                              withBoolean:(jboolean)enable {
  return LibOrgBouncycastleUtilProperties_setThreadOverrideWithNSString_withBoolean_(propertyName, enable);
}

+ (jboolean)removeThreadOverrideWithNSString:(NSString *)propertyName {
  return LibOrgBouncycastleUtilProperties_removeThreadOverrideWithNSString_(propertyName);
}

+ (JavaMathBigInteger *)asBigIntegerWithNSString:(NSString *)propertyName {
  return LibOrgBouncycastleUtilProperties_asBigIntegerWithNSString_(propertyName);
}

+ (id<JavaUtilSet>)asKeySetWithNSString:(NSString *)propertyName {
  return LibOrgBouncycastleUtilProperties_asKeySetWithNSString_(propertyName);
}

+ (NSString *)fetchPropertyWithNSString:(NSString *)propertyName {
  return LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(propertyName);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 4, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 5, 1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x9, 6, 1, -1, 7, -1, -1 },
    { NULL, "LNSString;", 0xa, 8, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isOverrideSetWithNSString:);
  methods[2].selector = @selector(setThreadOverrideWithNSString:withBoolean:);
  methods[3].selector = @selector(removeThreadOverrideWithNSString:);
  methods[4].selector = @selector(asBigIntegerWithNSString:);
  methods[5].selector = @selector(asKeySetWithNSString:);
  methods[6].selector = @selector(fetchPropertyWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "threadProperties", "LJavaLangThreadLocal;", .constantValue.asLong = 0, 0x1a, -1, 9, -1, -1 },
  };
  static const void *ptrTable[] = { "isOverrideSet", "LNSString;", "setThreadOverride", "LNSString;Z", "removeThreadOverride", "asBigInteger", "asKeySet", "(Ljava/lang/String;)Ljava/util/Set<Ljava/lang/String;>;", "fetchProperty", &LibOrgBouncycastleUtilProperties_threadProperties };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilProperties = { "Properties", "lib.org.bouncycastle.util", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilProperties;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleUtilProperties class]) {
    LibOrgBouncycastleUtilProperties_threadProperties = new_JavaLangThreadLocal_init();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleUtilProperties)
  }
}

@end

void LibOrgBouncycastleUtilProperties_init(LibOrgBouncycastleUtilProperties *self) {
  NSObject_init(self);
}

LibOrgBouncycastleUtilProperties *new_LibOrgBouncycastleUtilProperties_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilProperties, init)
}

LibOrgBouncycastleUtilProperties *create_LibOrgBouncycastleUtilProperties_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilProperties, init)
}

jboolean LibOrgBouncycastleUtilProperties_isOverrideSetWithNSString_(NSString *propertyName) {
  LibOrgBouncycastleUtilProperties_initialize();
  @try {
    NSString *p = LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(propertyName);
    if (p != nil) {
      return [@"true" isEqual:LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_(p)];
    }
    return false;
  }
  @catch (JavaSecurityAccessControlException *e) {
    return false;
  }
}

jboolean LibOrgBouncycastleUtilProperties_setThreadOverrideWithNSString_withBoolean_(NSString *propertyName, jboolean enable) {
  LibOrgBouncycastleUtilProperties_initialize();
  jboolean isSet = LibOrgBouncycastleUtilProperties_isOverrideSetWithNSString_(propertyName);
  id<JavaUtilMap> localProps = (id<JavaUtilMap>) cast_check([((JavaLangThreadLocal *) nil_chk(LibOrgBouncycastleUtilProperties_threadProperties)) get], JavaUtilMap_class_());
  if (localProps == nil) {
    localProps = new_JavaUtilHashMap_init();
  }
  (void) [localProps putWithId:propertyName withId:enable ? @"true" : @"false"];
  [LibOrgBouncycastleUtilProperties_threadProperties setWithId:localProps];
  return isSet;
}

jboolean LibOrgBouncycastleUtilProperties_removeThreadOverrideWithNSString_(NSString *propertyName) {
  LibOrgBouncycastleUtilProperties_initialize();
  jboolean isSet = LibOrgBouncycastleUtilProperties_isOverrideSetWithNSString_(propertyName);
  id<JavaUtilMap> localProps = (id<JavaUtilMap>) cast_check([((JavaLangThreadLocal *) nil_chk(LibOrgBouncycastleUtilProperties_threadProperties)) get], JavaUtilMap_class_());
  if (localProps == nil) {
    return false;
  }
  (void) [localProps removeWithId:propertyName];
  if ([localProps isEmpty]) {
    [LibOrgBouncycastleUtilProperties_threadProperties remove];
  }
  else {
    [LibOrgBouncycastleUtilProperties_threadProperties setWithId:localProps];
  }
  return isSet;
}

JavaMathBigInteger *LibOrgBouncycastleUtilProperties_asBigIntegerWithNSString_(NSString *propertyName) {
  LibOrgBouncycastleUtilProperties_initialize();
  NSString *p = LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(propertyName);
  if (p != nil) {
    return new_JavaMathBigInteger_initWithNSString_(p);
  }
  return nil;
}

id<JavaUtilSet> LibOrgBouncycastleUtilProperties_asKeySetWithNSString_(NSString *propertyName) {
  LibOrgBouncycastleUtilProperties_initialize();
  id<JavaUtilSet> set = new_JavaUtilHashSet_init();
  NSString *p = LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(propertyName);
  if (p != nil) {
    JavaUtilStringTokenizer *sTok = new_JavaUtilStringTokenizer_initWithNSString_withNSString_(p, @",");
    while ([sTok hasMoreElements]) {
      [set addWithId:[((NSString *) nil_chk(LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_([sTok nextToken]))) java_trim]];
    }
  }
  return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(set);
}

NSString *LibOrgBouncycastleUtilProperties_fetchPropertyWithNSString_(NSString *propertyName) {
  LibOrgBouncycastleUtilProperties_initialize();
  return (NSString *) cast_chk(JavaSecurityAccessController_doPrivilegedWithJavaSecurityPrivilegedAction_(new_LibOrgBouncycastleUtilProperties_1_initWithNSString_(propertyName)), [NSString class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilProperties)

@implementation LibOrgBouncycastleUtilProperties_1

- (instancetype)initWithNSString:(NSString *)capture$0 {
  LibOrgBouncycastleUtilProperties_1_initWithNSString_(self, capture$0);
  return self;
}

- (id)run {
  id<JavaUtilMap> localProps = (id<JavaUtilMap>) cast_check([((JavaLangThreadLocal *) nil_chk(JreLoadStatic(LibOrgBouncycastleUtilProperties, threadProperties))) get], JavaUtilMap_class_());
  if (localProps != nil) {
    return [localProps getWithId:val$propertyName_];
  }
  return JavaLangSystem_getPropertyWithNSString_(val$propertyName_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(run);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$propertyName_", "LNSString;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleUtilProperties;", "fetchPropertyWithNSString:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilProperties_1 = { "", "lib.org.bouncycastle.util", ptrTable, methods, fields, 7, 0x8018, 2, 1, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleUtilProperties_1;
}

@end

void LibOrgBouncycastleUtilProperties_1_initWithNSString_(LibOrgBouncycastleUtilProperties_1 *self, NSString *capture$0) {
  self->val$propertyName_ = capture$0;
  NSObject_init(self);
}

LibOrgBouncycastleUtilProperties_1 *new_LibOrgBouncycastleUtilProperties_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilProperties_1, initWithNSString_, capture$0)
}

LibOrgBouncycastleUtilProperties_1 *create_LibOrgBouncycastleUtilProperties_1_initWithNSString_(NSString *capture$0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilProperties_1, initWithNSString_, capture$0)
}