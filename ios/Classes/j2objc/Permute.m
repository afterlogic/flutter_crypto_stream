//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/sphincs/Permute.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Pack.h"
#include "Permute.h"
#include "java/lang/IllegalArgumentException.h"

inline jint LibOrgBouncycastlePqcCryptoSphincsPermute_get_CHACHA_ROUNDS(void);
#define LibOrgBouncycastlePqcCryptoSphincsPermute_CHACHA_ROUNDS 12
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoSphincsPermute, CHACHA_ROUNDS, jint)

@implementation LibOrgBouncycastlePqcCryptoSphincsPermute

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoSphincsPermute_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)rotlWithInt:(jint)x
            withInt:(jint)y {
  return LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x, y);
}

+ (void)permuteWithInt:(jint)rounds
          withIntArray:(IOSIntArray *)x {
  LibOrgBouncycastlePqcCryptoSphincsPermute_permuteWithInt_withIntArray_(rounds, x);
}

- (void)chacha_permuteWithByteArray:(IOSByteArray *)outArg
                      withByteArray:(IOSByteArray *)inArg {
  jint i;
  IOSIntArray *x = [IOSIntArray newArrayWithLength:16];
  for (i = 0; i < 16; i++) {
    *IOSIntArray_GetRef(x, i) = LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_(inArg, 4 * i);
  }
  LibOrgBouncycastlePqcCryptoSphincsPermute_permuteWithInt_withIntArray_(LibOrgBouncycastlePqcCryptoSphincsPermute_CHACHA_ROUNDS, x);
  for (i = 0; i < 16; ++i) {
    LibOrgBouncycastleUtilPack_intToLittleEndianWithInt_withByteArray_withInt_(IOSIntArray_Get(x, i), outArg, 4 * i);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(rotlWithInt:withInt:);
  methods[2].selector = @selector(permuteWithInt:withIntArray:);
  methods[3].selector = @selector(chacha_permuteWithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "CHACHA_ROUNDS", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoSphincsPermute_CHACHA_ROUNDS, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "rotl", "II", "permute", "I[I", "chacha_permute", "[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoSphincsPermute = { "Permute", "lib.org.bouncycastle.pqc.crypto.sphincs", ptrTable, methods, fields, 7, 0x0, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoSphincsPermute;
}

@end

void LibOrgBouncycastlePqcCryptoSphincsPermute_init(LibOrgBouncycastlePqcCryptoSphincsPermute *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoSphincsPermute *new_LibOrgBouncycastlePqcCryptoSphincsPermute_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoSphincsPermute, init)
}

LibOrgBouncycastlePqcCryptoSphincsPermute *create_LibOrgBouncycastlePqcCryptoSphincsPermute_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoSphincsPermute, init)
}

jint LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(jint x, jint y) {
  LibOrgBouncycastlePqcCryptoSphincsPermute_initialize();
  return (JreLShift32(x, y)) | (JreURShift32(x, -y));
}

void LibOrgBouncycastlePqcCryptoSphincsPermute_permuteWithInt_withIntArray_(jint rounds, IOSIntArray *x) {
  LibOrgBouncycastlePqcCryptoSphincsPermute_initialize();
  if (((IOSIntArray *) nil_chk(x))->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_init();
  }
  if (rounds % 2 != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Number of rounds must be even");
  }
  jint x00 = IOSIntArray_Get(x, 0);
  jint x01 = IOSIntArray_Get(x, 1);
  jint x02 = IOSIntArray_Get(x, 2);
  jint x03 = IOSIntArray_Get(x, 3);
  jint x04 = IOSIntArray_Get(x, 4);
  jint x05 = IOSIntArray_Get(x, 5);
  jint x06 = IOSIntArray_Get(x, 6);
  jint x07 = IOSIntArray_Get(x, 7);
  jint x08 = IOSIntArray_Get(x, 8);
  jint x09 = IOSIntArray_Get(x, 9);
  jint x10 = IOSIntArray_Get(x, 10);
  jint x11 = IOSIntArray_Get(x, 11);
  jint x12 = IOSIntArray_Get(x, 12);
  jint x13 = IOSIntArray_Get(x, 13);
  jint x14 = IOSIntArray_Get(x, 14);
  jint x15 = IOSIntArray_Get(x, 15);
  for (jint i = rounds; i > 0; i -= 2) {
    x00 += x04;
    x12 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x12 ^ x00, 16);
    x08 += x12;
    x04 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x04 ^ x08, 12);
    x00 += x04;
    x12 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x12 ^ x00, 8);
    x08 += x12;
    x04 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x04 ^ x08, 7);
    x01 += x05;
    x13 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x13 ^ x01, 16);
    x09 += x13;
    x05 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x05 ^ x09, 12);
    x01 += x05;
    x13 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x13 ^ x01, 8);
    x09 += x13;
    x05 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x05 ^ x09, 7);
    x02 += x06;
    x14 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x14 ^ x02, 16);
    x10 += x14;
    x06 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x06 ^ x10, 12);
    x02 += x06;
    x14 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x14 ^ x02, 8);
    x10 += x14;
    x06 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x06 ^ x10, 7);
    x03 += x07;
    x15 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x15 ^ x03, 16);
    x11 += x15;
    x07 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x07 ^ x11, 12);
    x03 += x07;
    x15 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x15 ^ x03, 8);
    x11 += x15;
    x07 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x07 ^ x11, 7);
    x00 += x05;
    x15 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x15 ^ x00, 16);
    x10 += x15;
    x05 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x05 ^ x10, 12);
    x00 += x05;
    x15 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x15 ^ x00, 8);
    x10 += x15;
    x05 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x05 ^ x10, 7);
    x01 += x06;
    x12 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x12 ^ x01, 16);
    x11 += x12;
    x06 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x06 ^ x11, 12);
    x01 += x06;
    x12 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x12 ^ x01, 8);
    x11 += x12;
    x06 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x06 ^ x11, 7);
    x02 += x07;
    x13 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x13 ^ x02, 16);
    x08 += x13;
    x07 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x07 ^ x08, 12);
    x02 += x07;
    x13 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x13 ^ x02, 8);
    x08 += x13;
    x07 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x07 ^ x08, 7);
    x03 += x04;
    x14 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x14 ^ x03, 16);
    x09 += x14;
    x04 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x04 ^ x09, 12);
    x03 += x04;
    x14 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x14 ^ x03, 8);
    x09 += x14;
    x04 = LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(x04 ^ x09, 7);
  }
  *IOSIntArray_GetRef(x, 0) = x00;
  *IOSIntArray_GetRef(x, 1) = x01;
  *IOSIntArray_GetRef(x, 2) = x02;
  *IOSIntArray_GetRef(x, 3) = x03;
  *IOSIntArray_GetRef(x, 4) = x04;
  *IOSIntArray_GetRef(x, 5) = x05;
  *IOSIntArray_GetRef(x, 6) = x06;
  *IOSIntArray_GetRef(x, 7) = x07;
  *IOSIntArray_GetRef(x, 8) = x08;
  *IOSIntArray_GetRef(x, 9) = x09;
  *IOSIntArray_GetRef(x, 10) = x10;
  *IOSIntArray_GetRef(x, 11) = x11;
  *IOSIntArray_GetRef(x, 12) = x12;
  *IOSIntArray_GetRef(x, 13) = x13;
  *IOSIntArray_GetRef(x, 14) = x14;
  *IOSIntArray_GetRef(x, 15) = x15;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoSphincsPermute)
