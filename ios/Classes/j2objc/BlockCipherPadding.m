//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/paddings/BlockCipherPadding.java
//

#include "BlockCipherPadding.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoPaddingsBlockCipherPadding : NSObject

@end

@implementation LibOrgBouncycastleCryptoPaddingsBlockCipherPadding

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x401, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x401, 5, 6, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(getPaddingName);
  methods[2].selector = @selector(addPaddingWithByteArray:withInt:);
  methods[3].selector = @selector(padCountWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LJavaSecuritySecureRandom;", "LJavaLangIllegalArgumentException;", "addPadding", "[BI", "padCount", "[B", "LLibOrgBouncycastleCryptoInvalidCipherTextException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPaddingsBlockCipherPadding = { "BlockCipherPadding", "lib.org.bouncycastle.crypto.paddings", ptrTable, methods, NULL, 7, 0x609, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPaddingsBlockCipherPadding;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPaddingsBlockCipherPadding)