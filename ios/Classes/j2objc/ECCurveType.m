//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ECCurveType.java
//

#include "ECCurveType.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleCryptoTlsECCurveType

+ (jshort)explicit_prime {
  return LibOrgBouncycastleCryptoTlsECCurveType_explicit_prime;
}

+ (jshort)explicit_char2 {
  return LibOrgBouncycastleCryptoTlsECCurveType_explicit_char2;
}

+ (jshort)named_curve {
  return LibOrgBouncycastleCryptoTlsECCurveType_named_curve;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsECCurveType_init(self);
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
    { "explicit_prime", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsECCurveType_explicit_prime, 0x19, -1, -1, -1, -1 },
    { "explicit_char2", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsECCurveType_explicit_char2, 0x19, -1, -1, -1, -1 },
    { "named_curve", "S", .constantValue.asShort = LibOrgBouncycastleCryptoTlsECCurveType_named_curve, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsECCurveType = { "ECCurveType", "lib.org.bouncycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsECCurveType;
}

@end

void LibOrgBouncycastleCryptoTlsECCurveType_init(LibOrgBouncycastleCryptoTlsECCurveType *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoTlsECCurveType *new_LibOrgBouncycastleCryptoTlsECCurveType_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsECCurveType, init)
}

LibOrgBouncycastleCryptoTlsECCurveType *create_LibOrgBouncycastleCryptoTlsECCurveType_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsECCurveType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsECCurveType)
