//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/CryptoServicesPermission.java
//

#include "CryptoServicesPermission.h"
#include "J2ObjC_source.h"
#include "java/security/Permission.h"
#include "java/util/HashSet.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleCryptoCryptoServicesPermission () {
 @public
  id<JavaUtilSet> actions_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoCryptoServicesPermission, actions_, id<JavaUtilSet>)

NSString *LibOrgBouncycastleCryptoCryptoServicesPermission_GLOBAL_CONFIG = @"globalConfig";
NSString *LibOrgBouncycastleCryptoCryptoServicesPermission_THREAD_LOCAL_CONFIG = @"threadLocalConfig";
NSString *LibOrgBouncycastleCryptoCryptoServicesPermission_DEFAULT_RANDOM = @"defaultRandomConfig";

@implementation LibOrgBouncycastleCryptoCryptoServicesPermission

+ (NSString *)GLOBAL_CONFIG {
  return LibOrgBouncycastleCryptoCryptoServicesPermission_GLOBAL_CONFIG;
}

+ (NSString *)THREAD_LOCAL_CONFIG {
  return LibOrgBouncycastleCryptoCryptoServicesPermission_THREAD_LOCAL_CONFIG;
}

+ (NSString *)DEFAULT_RANDOM {
  return LibOrgBouncycastleCryptoCryptoServicesPermission_DEFAULT_RANDOM;
}

- (instancetype)initWithNSString:(NSString *)name {
  LibOrgBouncycastleCryptoCryptoServicesPermission_initWithNSString_(self, name);
  return self;
}

- (jboolean)impliesWithJavaSecurityPermission:(JavaSecurityPermission *)permission {
  if ([permission isKindOfClass:[LibOrgBouncycastleCryptoCryptoServicesPermission class]]) {
    LibOrgBouncycastleCryptoCryptoServicesPermission *other = (LibOrgBouncycastleCryptoCryptoServicesPermission *) permission;
    if ([((NSString *) nil_chk([self getName])) isEqual:[((LibOrgBouncycastleCryptoCryptoServicesPermission *) nil_chk(other)) getName]]) {
      return true;
    }
    if ([((id<JavaUtilSet>) nil_chk(self->actions_)) containsAllWithJavaUtilCollection:other->actions_]) {
      return true;
    }
  }
  return false;
}

- (jboolean)isEqual:(id)obj {
  if ([obj isKindOfClass:[LibOrgBouncycastleCryptoCryptoServicesPermission class]]) {
    LibOrgBouncycastleCryptoCryptoServicesPermission *other = (LibOrgBouncycastleCryptoCryptoServicesPermission *) obj;
    if ([((id<JavaUtilSet>) nil_chk(self->actions_)) isEqual:((LibOrgBouncycastleCryptoCryptoServicesPermission *) nil_chk(other))->actions_]) {
      return true;
    }
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((id<JavaUtilSet>) nil_chk(actions_)) hash]);
}

- (NSString *)getActions {
  return [((id<JavaUtilSet>) nil_chk(actions_)) description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(impliesWithJavaSecurityPermission:);
  methods[2].selector = @selector(isEqual:);
  methods[3].selector = @selector(hash);
  methods[4].selector = @selector(getActions);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "GLOBAL_CONFIG", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
    { "THREAD_LOCAL_CONFIG", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
    { "DEFAULT_RANDOM", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "actions_", "LJavaUtilSet;", .constantValue.asLong = 0, 0x12, -1, -1, 9, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "implies", "LJavaSecurityPermission;", "equals", "LNSObject;", "hashCode", &LibOrgBouncycastleCryptoCryptoServicesPermission_GLOBAL_CONFIG, &LibOrgBouncycastleCryptoCryptoServicesPermission_THREAD_LOCAL_CONFIG, &LibOrgBouncycastleCryptoCryptoServicesPermission_DEFAULT_RANDOM, "Ljava/util/Set<Ljava/lang/String;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoCryptoServicesPermission = { "CryptoServicesPermission", "lib.org.bouncycastle.crypto", ptrTable, methods, fields, 7, 0x1, 5, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoCryptoServicesPermission;
}

@end

void LibOrgBouncycastleCryptoCryptoServicesPermission_initWithNSString_(LibOrgBouncycastleCryptoCryptoServicesPermission *self, NSString *name) {
  JavaSecurityPermission_initWithNSString_(self, name);
  self->actions_ = new_JavaUtilHashSet_init();
  [self->actions_ addWithId:name];
}

LibOrgBouncycastleCryptoCryptoServicesPermission *new_LibOrgBouncycastleCryptoCryptoServicesPermission_initWithNSString_(NSString *name) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoCryptoServicesPermission, initWithNSString_, name)
}

LibOrgBouncycastleCryptoCryptoServicesPermission *create_LibOrgBouncycastleCryptoCryptoServicesPermission_initWithNSString_(NSString *name) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoCryptoServicesPermission, initWithNSString_, name)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoCryptoServicesPermission)
