//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ClientAuthenticationType.java
//

#include "ClientAuthenticationType.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsClientAuthenticationType

+ (jshort)anonymous {
  return LibOrgBouncycastleCryptoTlsClientAuthenticationType_anonymous;
}

+ (jshort)certificate_based {
  return LibOrgBouncycastleCryptoTlsClientAuthenticationType_certificate_based;
}

+ (jshort)psk {
  return LibOrgBouncycastleCryptoTlsClientAuthenticationType_psk;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsClientAuthenticationType_init(self);
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
    { "anonymous", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsClientAuthenticationType_anonymous, 0x19, -1, -1, -1, -1 },
    { "certificate_based", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsClientAuthenticationType_certificate_based, 0x19, -1, -1, -1, -1 },
    { "psk", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsClientAuthenticationType_psk, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsClientAuthenticationType = { "ClientAuthenticationType", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsClientAuthenticationType;
}

@end

void LibOrgBouncycastleCryptoTlsClientAuthenticationType_init(LibOrgBouncycastleCryptoTlsClientAuthenticationType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsClientAuthenticationType *new_LibOrgBouncycastleCryptoTlsClientAuthenticationType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsClientAuthenticationType, init)
}

LibOrgBouncycastleCryptoTlsClientAuthenticationType *create_LibOrgBouncycastleCryptoTlsClientAuthenticationType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsClientAuthenticationType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsClientAuthenticationType)
