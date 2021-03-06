//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/config/ProviderConfigurationPermission.java
//

#include "J2ObjC_source.h"
#include "ProviderConfigurationPermission.h"
#include "Strings.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/BasicPermission.h"
#include "java/security/Permission.h"
#include "java/util/StringTokenizer.h"

@interface LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission () {
 @public
  NSString *actions_;
  jint permissionMask_;
}

- (jint)calculateMaskWithNSString:(NSString *)actions;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, actions_, NSString *)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_THREAD_LOCAL_EC_IMPLICITLY_CA(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, THREAD_LOCAL_EC_IMPLICITLY_CA, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_EC_IMPLICITLY_CA(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, EC_IMPLICITLY_CA, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_THREAD_LOCAL_DH_DEFAULT_PARAMS(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, THREAD_LOCAL_DH_DEFAULT_PARAMS, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_DH_DEFAULT_PARAMS(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, DH_DEFAULT_PARAMS, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ACCEPTABLE_EC_CURVES(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ACCEPTABLE_EC_CURVES, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ADDITIONAL_EC_PARAMETERS(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ADDITIONAL_EC_PARAMETERS, jint)

inline jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ALL(void);
#define LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL 63
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ALL, jint)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_THREAD_LOCAL_EC_IMPLICITLY_CA_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR = @"threadlocalecimplicitlyca";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, THREAD_LOCAL_EC_IMPLICITLY_CA_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_EC_IMPLICITLY_CA_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR = @"ecimplicitlyca";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, EC_IMPLICITLY_CA_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR = @"threadlocaldhdefaultparams";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, THREAD_LOCAL_DH_DEFAULT_PARAMS_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_DH_DEFAULT_PARAMS_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR = @"dhdefaultparams";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, DH_DEFAULT_PARAMS_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ACCEPTABLE_EC_CURVES_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES_STR = @"acceptableeccurves";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ACCEPTABLE_EC_CURVES_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ADDITIONAL_EC_PARAMETERS_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS_STR = @"additionalecparameters";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ADDITIONAL_EC_PARAMETERS_STR, NSString *)

inline NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_get_ALL_STR(void);
static NSString *LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL_STR = @"all";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, ALL_STR, NSString *)

__attribute__((unused)) static jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_calculateMaskWithNSString_(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *self, NSString *actions);

@implementation LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission

- (instancetype)initWithNSString:(NSString *)name {
  LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_(self, name);
  return self;
}

- (instancetype)initWithNSString:(NSString *)name
                    withNSString:(NSString *)actions {
  LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_withNSString_(self, name, actions);
  return self;
}

- (jint)calculateMaskWithNSString:(NSString *)actions {
  return LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_calculateMaskWithNSString_(self, actions);
}

- (NSString *)getActions {
  return actions_;
}

- (jboolean)impliesWithJavaSecurityPermission:(JavaSecurityPermission *)permission {
  if (!([permission isKindOfClass:[LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission class]])) {
    return false;
  }
  if (![((NSString *) nil_chk([self getName])) isEqual:[((JavaSecurityPermission *) nil_chk(permission)) getName]]) {
    return false;
  }
  LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *other = (LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *) cast_chk(permission, [LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission class]);
  return (self->permissionMask_ & other->permissionMask_) == other->permissionMask_;
}

- (jboolean)isEqual:(id)obj {
  if (obj == self) {
    return true;
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission class]]) {
    LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *other = (LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *) obj;
    return self->permissionMask_ == ((LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *) nil_chk(other))->permissionMask_ && [((NSString *) nil_chk([self getName])) isEqual:[other getName]];
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((NSString *) nil_chk([self getName])) hash]) + self->permissionMask_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 2, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 7, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithNSString:withNSString:);
  methods[2].selector = @selector(calculateMaskWithNSString:);
  methods[3].selector = @selector(getActions);
  methods[4].selector = @selector(impliesWithJavaSecurityPermission:);
  methods[5].selector = @selector(isEqual:);
  methods[6].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "THREAD_LOCAL_EC_IMPLICITLY_CA", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA, 0x1a, -1, -1, -1, -1 },
    { "EC_IMPLICITLY_CA", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA, 0x1a, -1, -1, -1, -1 },
    { "THREAD_LOCAL_DH_DEFAULT_PARAMS", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS, 0x1a, -1, -1, -1, -1 },
    { "DH_DEFAULT_PARAMS", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS, 0x1a, -1, -1, -1, -1 },
    { "ACCEPTABLE_EC_CURVES", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES, 0x1a, -1, -1, -1, -1 },
    { "ADDITIONAL_EC_PARAMETERS", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS, 0x1a, -1, -1, -1, -1 },
    { "ALL", "I", .constantValue.asInt = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL, 0x1a, -1, -1, -1, -1 },
    { "THREAD_LOCAL_EC_IMPLICITLY_CA_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
    { "EC_IMPLICITLY_CA_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 9, -1, -1 },
    { "THREAD_LOCAL_DH_DEFAULT_PARAMS_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "DH_DEFAULT_PARAMS_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "ACCEPTABLE_EC_CURVES_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "ADDITIONAL_EC_PARAMETERS_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "ALL_STR", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "actions_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "permissionMask_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LNSString;LNSString;", "calculateMask", "implies", "LJavaSecurityPermission;", "equals", "LNSObject;", "hashCode", &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS_STR, &LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL_STR };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission = { "ProviderConfigurationPermission", "lib.org.bouncycastle.jcajce.provider.config", ptrTable, methods, fields, 7, 0x1, 7, 16, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission;
}

@end

void LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *self, NSString *name) {
  JavaSecurityBasicPermission_initWithNSString_(self, name);
  self->actions_ = @"all";
  self->permissionMask_ = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL;
}

LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *new_LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_(NSString *name) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, initWithNSString_, name)
}

LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *create_LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_(NSString *name) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, initWithNSString_, name)
}

void LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_withNSString_(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *self, NSString *name, NSString *actions) {
  JavaSecurityBasicPermission_initWithNSString_withNSString_(self, name, actions);
  self->actions_ = actions;
  self->permissionMask_ = LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_calculateMaskWithNSString_(self, actions);
}

LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *new_LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_withNSString_(NSString *name, NSString *actions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, initWithNSString_withNSString_, name, actions)
}

LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *create_LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_initWithNSString_withNSString_(NSString *name, NSString *actions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission, initWithNSString_withNSString_, name, actions)
}

jint LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_calculateMaskWithNSString_(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission *self, NSString *actions) {
  JavaUtilStringTokenizer *tok = new_JavaUtilStringTokenizer_initWithNSString_withNSString_(LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_(actions), @" ,");
  jint mask = 0;
  while ([tok hasMoreTokens]) {
    NSString *s = [tok nextToken];
    if ([((NSString *) nil_chk(s)) isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_EC_IMPLICITLY_CA;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_EC_IMPLICITLY_CA;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_THREAD_LOCAL_DH_DEFAULT_PARAMS;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_DH_DEFAULT_PARAMS;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ACCEPTABLE_EC_CURVES;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ADDITIONAL_EC_PARAMETERS;
    }
    else if ([s isEqual:LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL_STR]) {
      mask |= LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission_ALL;
    }
  }
  if (mask == 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown permissions passed to mask");
  }
  return mask;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderConfigProviderConfigurationPermission)
