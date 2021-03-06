//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/KeyEncapsulation.java
//

#include "J2ObjC_source.h"
#include "KeyEncapsulation.h"

@interface LibOrgBouncycastleCryptoKeyEncapsulation : NSObject

@end

@implementation LibOrgBouncycastleCryptoKeyEncapsulation

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x401, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[1].selector = @selector(encryptWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(decryptWithByteArray:withInt:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "encrypt", "[BII", "decrypt", "[BIII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoKeyEncapsulation = { "KeyEncapsulation", "lib.org.bouncycastle.crypto", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoKeyEncapsulation;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoKeyEncapsulation)
