//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/UserMappingType.java
//

#include "J2ObjC_source.h"
#include "UserMappingType.h"

@implementation LibOrgBouncycastleCryptoTlsUserMappingType

+ (jshort)upn_domain_hint {
  return LibOrgBouncycastleCryptoTlsUserMappingType_upn_domain_hint;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsUserMappingType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "upn_domain_hint", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsUserMappingType_upn_domain_hint, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsUserMappingType = { "UserMappingType", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsUserMappingType;
}

@end

void LibOrgBouncycastleCryptoTlsUserMappingType_init(LibOrgBouncycastleCryptoTlsUserMappingType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsUserMappingType *new_LibOrgBouncycastleCryptoTlsUserMappingType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsUserMappingType, init)
}

LibOrgBouncycastleCryptoTlsUserMappingType *create_LibOrgBouncycastleCryptoTlsUserMappingType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsUserMappingType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsUserMappingType)
