//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/JcajceGOST28147ParameterSpec.java
//

#include "ASN1ObjectIdentifier.h"
#include "Arrays.h"
#include "CryptoProObjectIdentifiers.h"
#include "GOST28147Engine.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceGOST28147ParameterSpec.h"
#include "RosstandartObjectIdentifiers.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"

@interface LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec () {
 @public
  IOSByteArray *iv_;
  IOSByteArray *sBox_;
}

+ (NSString *)getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sBoxOid;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, sBox_, IOSByteArray *)

inline id<JavaUtilMap> LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_get_oidMappings(void);
inline id<JavaUtilMap> LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_set_oidMappings(id<JavaUtilMap> value);
static id<JavaUtilMap> LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, oidMappings, id<JavaUtilMap>)

__attribute__((unused)) static NSString *LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sBoxOid);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec)

@implementation LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec

- (instancetype)initWithByteArray:(IOSByteArray *)sBox {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_(self, sBox);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)sBox
                    withByteArray:(IOSByteArray *)iv {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_withByteArray_(self, sBox, iv);
  return self;
}

- (instancetype)initWithNSString:(NSString *)sBoxName {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(self, sBoxName);
  return self;
}

- (instancetype)initWithNSString:(NSString *)sBoxName
                   withByteArray:(IOSByteArray *)iv {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_withByteArray_(self, sBoxName, iv);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sBoxName
                                                     withByteArray:(IOSByteArray *)iv {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(self, sBoxName, iv);
  return self;
}

- (IOSByteArray *)getSbox {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(sBox_);
}

- (IOSByteArray *)getSBox {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(sBox_);
}

- (IOSByteArray *)getIV {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(iv_);
}

+ (NSString *)getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sBoxOid {
  return LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(sBoxOid);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithByteArray:withByteArray:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(initWithNSString:withByteArray:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withByteArray:);
  methods[5].selector = @selector(getSbox);
  methods[6].selector = @selector(getSBox);
  methods[7].selector = @selector(getIV);
  methods[8].selector = @selector(getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sBox_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "oidMappings", "LJavaUtilMap;", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "[B[B", "LNSString;", "LNSString;[B", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;[B", "getName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", &LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec = { "JcajceGOST28147ParameterSpec", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec class]) {
    LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings = new_JavaUtilHashMap_init();
    {
      (void) [LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_A_ParamSet) withId:@"E-A"];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_B_ParamSet) withId:@"E-B"];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_C_ParamSet) withId:@"E-C"];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, id_Gost28147_89_CryptoPro_D_ParamSet) withId:@"E-D"];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings)) putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_28147_param_Z) withId:@"Param-Z"];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec)
  }
}

@end

void LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *self, IOSByteArray *sBox) {
  NSObject_init(self);
  self->iv_ = nil;
  self->sBox_ = nil;
  self->sBox_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(sBox))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sBox, 0, self->sBox_, 0, sBox->size_);
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithByteArray_, sBox)
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithByteArray_, sBox)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_withByteArray_(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *self, IOSByteArray *sBox, IOSByteArray *iv) {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_(self, sBox);
  self->iv_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(iv))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, 0, iv->size_);
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithByteArray_withByteArray_, sBox, iv)
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithByteArray_withByteArray_, sBox, iv)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *self, NSString *sBoxName) {
  NSObject_init(self);
  self->iv_ = nil;
  self->sBox_ = nil;
  self->sBox_ = LibOrgBouncycastleCryptoEnginesGOST28147Engine_getSBoxWithNSString_(sBoxName);
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithNSString_, sBoxName)
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithNSString_, sBoxName)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_withByteArray_(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *self, NSString *sBoxName, IOSByteArray *iv) {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(self, sBoxName);
  self->iv_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(iv))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, 0, iv->size_);
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithNSString_withByteArray_, sBoxName, iv)
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithNSString_withByteArray_, sBoxName, iv)
}

void LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithNSString_(self, LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(sBoxName));
  self->iv_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(iv);
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *new_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_, sBoxName, iv)
}

LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec *create_LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_, sBoxName, iv)
}

NSString *LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sBoxOid) {
  LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_initialize();
  NSString *sBoxName = (NSString *) cast_chk([((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec_oidMappings)) getWithId:sBoxOid], [NSString class]);
  if (sBoxName == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"unknown OID: ", sBoxOid));
  }
  return sBoxName;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecJcajceGOST28147ParameterSpec)
