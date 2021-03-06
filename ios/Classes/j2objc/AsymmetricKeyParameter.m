//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/AsymmetricKeyParameter.java
//

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter

- (instancetype)initWithBoolean:(jboolean)privateKey {
  LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, privateKey);
  return self;
}

- (jboolean)isPrivate {
  return privateKey_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:);
  methods[1].selector = @selector(isPrivate);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter = { "AsymmetricKeyParameter", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
}

@end

void LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *self, jboolean privateKey) {
  NSObject_init(self);
  self->privateKey_ = privateKey;
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *new_LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(jboolean privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter, initWithBoolean_, privateKey)
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *create_LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(jboolean privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter, initWithBoolean_, privateKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter)
