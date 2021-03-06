//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/X448Agreement.java
//

#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X448Agreement.h"
#include "X448PrivateKeyParameters.h"
#include "X448PublicKeyParameters.h"

@interface LibOrgBouncycastleCryptoAgreementX448Agreement () {
 @public
  LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters *privateKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoAgreementX448Agreement, privateKey_, LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters *)

@implementation LibOrgBouncycastleCryptoAgreementX448Agreement

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementX448Agreement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  self->privateKey_ = (LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters class]);
}

- (jint)getAgreementSize {
  return LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters_SECRET_SIZE;
}

- (void)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)publicKey
                                                         withByteArray:(IOSByteArray *)buf
                                                               withInt:(jint)off {
  [((LibOrgBouncycastleCryptoParamsX448PrivateKeyParameters *) nil_chk(privateKey_)) generateSecretWithLibOrgBouncycastleCryptoParamsX448PublicKeyParameters:(LibOrgBouncycastleCryptoParamsX448PublicKeyParameters *) cast_chk(publicKey, [LibOrgBouncycastleCryptoParamsX448PublicKeyParameters class]) withByteArray:buf withInt:off];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAgreementSize);
  methods[3].selector = @selector(calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsX448PrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "calculateAgreement", "LLibOrgBouncycastleCryptoCipherParameters;[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementX448Agreement = { "X448Agreement", "lib.org.bouncycastle.crypto.agreement", ptrTable, methods, fields, 7, 0x11, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementX448Agreement;
}

@end

void LibOrgBouncycastleCryptoAgreementX448Agreement_init(LibOrgBouncycastleCryptoAgreementX448Agreement *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementX448Agreement *new_LibOrgBouncycastleCryptoAgreementX448Agreement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementX448Agreement, init)
}

LibOrgBouncycastleCryptoAgreementX448Agreement *create_LibOrgBouncycastleCryptoAgreementX448Agreement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementX448Agreement, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementX448Agreement)
