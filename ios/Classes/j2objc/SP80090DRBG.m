//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/drbg/SP80090DRBG.java
//

#include "J2ObjC_source.h"
#include "SP80090DRBG.h"

@interface LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG : NSObject

@end

@implementation LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getBlockSize);
  methods[1].selector = @selector(generateWithByteArray:withByteArray:withBoolean:);
  methods[2].selector = @selector(reseedWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generate", "[B[BZ", "reseed", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG = { "SP80090DRBG", "lib.org.bouncycastle.crypto.prng.drbg", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngDrbgSP80090DRBG)
