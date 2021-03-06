//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/WOTSPlusPrivateKeyParameters.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "WOTSPlusParameters.h"
#include "WOTSPlusPrivateKeyParameters.h"
#include "XMSSUtil.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters () {
 @public
  IOSObjectArray *privateKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters, privateKey_, IOSObjectArray *)

@implementation LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *)params
                                                           withByteArray2:(IOSObjectArray *)privateKey {
  LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(self, params, privateKey);
  return self;
}

- (IOSObjectArray *)toByteArray {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(privateKey_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "[[B", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters:withByteArray2:);
  methods[1].selector = @selector(toByteArray);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "[[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters;[[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters = { "WOTSPlusPrivateKeyParameters", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *privateKey) {
  NSObject_init(self);
  if (params == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  if (privateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"privateKey == null");
  }
  if (LibOrgBouncycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(privateKey)) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"privateKey byte array == null");
  }
  if (privateKey->size_ != [params getLen]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong privateKey format");
  }
  for (jint i = 0; i < privateKey->size_; i++) {
    if (((IOSByteArray *) nil_chk(IOSObjectArray_Get(privateKey, i)))->size_ != [params getDigestSize]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong privateKey format");
    }
  }
  self->privateKey_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(privateKey);
}

LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_, params, privateKey)
}

LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_, params, privateKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPrivateKeyParameters)
