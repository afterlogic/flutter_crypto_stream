//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/CommonFunction.java
//

#include "CommonFunction.h"
#include "Const.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastlePqcCryptoQteslaCommonFunction

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)memoryEqualWithByteArray:(IOSByteArray *)left
                             withInt:(jint)leftOffset
                       withByteArray:(IOSByteArray *)right
                             withInt:(jint)rightOffset
                             withInt:(jint)length {
  return LibOrgBouncycastlePqcCryptoQteslaCommonFunction_memoryEqualWithByteArray_withInt_withByteArray_withInt_withInt_(left, leftOffset, right, rightOffset, length);
}

+ (jshort)load16WithByteArray:(IOSByteArray *)load_
                      withInt:(jint)loadOffset {
  return LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load16WithByteArray_withInt_(load_, loadOffset);
}

+ (jint)load32WithByteArray:(IOSByteArray *)load_
                    withInt:(jint)loadOffset {
  return LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load32WithByteArray_withInt_(load_, loadOffset);
}

+ (jlong)load64WithByteArray:(IOSByteArray *)load_
                     withInt:(jint)loadOffset {
  return LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load64WithByteArray_withInt_(load_, loadOffset);
}

+ (void)store16WithByteArray:(IOSByteArray *)store
                     withInt:(jint)storeOffset
                   withShort:(jshort)number {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store16WithByteArray_withInt_withShort_(store, storeOffset, number);
}

+ (void)store32WithByteArray:(IOSByteArray *)store
                     withInt:(jint)storeOffset
                     withInt:(jint)number {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store32WithByteArray_withInt_withInt_(store, storeOffset, number);
}

+ (void)store64WithByteArray:(IOSByteArray *)store
                     withInt:(jint)storeOffset
                    withLong:(jlong)number {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store64WithByteArray_withInt_withLong_(store, storeOffset, number);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "S", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 4, 3, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 5, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 10, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(memoryEqualWithByteArray:withInt:withByteArray:withInt:withInt:);
  methods[2].selector = @selector(load16WithByteArray:withInt:);
  methods[3].selector = @selector(load32WithByteArray:withInt:);
  methods[4].selector = @selector(load64WithByteArray:withInt:);
  methods[5].selector = @selector(store16WithByteArray:withInt:withShort:);
  methods[6].selector = @selector(store32WithByteArray:withInt:withInt:);
  methods[7].selector = @selector(store64WithByteArray:withInt:withLong:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "memoryEqual", "[BI[BII", "load16", "[BI", "load32", "load64", "store16", "[BIS", "store32", "[BII", "store64", "[BIJ" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoQteslaCommonFunction = { "CommonFunction", "lib.org.bouncycastle.pqc.crypto.qtesla", ptrTable, methods, NULL, 7, 0x0, 8, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoQteslaCommonFunction;
}

@end

void LibOrgBouncycastlePqcCryptoQteslaCommonFunction_init(LibOrgBouncycastlePqcCryptoQteslaCommonFunction *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoQteslaCommonFunction *new_LibOrgBouncycastlePqcCryptoQteslaCommonFunction_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoQteslaCommonFunction, init)
}

LibOrgBouncycastlePqcCryptoQteslaCommonFunction *create_LibOrgBouncycastlePqcCryptoQteslaCommonFunction_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoQteslaCommonFunction, init)
}

jboolean LibOrgBouncycastlePqcCryptoQteslaCommonFunction_memoryEqualWithByteArray_withInt_withByteArray_withInt_withInt_(IOSByteArray *left, jint leftOffset, IOSByteArray *right, jint rightOffset, jint length) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  if ((leftOffset + length <= ((IOSByteArray *) nil_chk(left))->size_) && (rightOffset + length <= ((IOSByteArray *) nil_chk(right))->size_)) {
    for (jint i = 0; i < length; i++) {
      if (IOSByteArray_Get(left, leftOffset + i) != IOSByteArray_Get(nil_chk(right), rightOffset + i)) {
        return false;
      }
    }
    return true;
  }
  else {
    return false;
  }
}

jshort LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load16WithByteArray_withInt_(IOSByteArray *load_, jint loadOffset) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  jshort number = 0;
  if (((IOSByteArray *) nil_chk(load_))->size_ - loadOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_SHORT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_SHORT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      number ^= JreLShift32((jshort) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  else {
    for (jint i = 0; i < load_->size_ - loadOffset; i++) {
      number ^= JreLShift32((jshort) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  return number;
}

jint LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load32WithByteArray_withInt_(IOSByteArray *load_, jint loadOffset) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  jint number = 0;
  if (((IOSByteArray *) nil_chk(load_))->size_ - loadOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_INT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_INT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      number ^= JreLShift32((jint) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  else {
    for (jint i = 0; i < load_->size_ - loadOffset; i++) {
      number ^= JreLShift32((jint) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  return number;
}

jlong LibOrgBouncycastlePqcCryptoQteslaCommonFunction_load64WithByteArray_withInt_(IOSByteArray *load_, jint loadOffset) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  jlong number = 0LL;
  if (((IOSByteArray *) nil_chk(load_))->size_ - loadOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_LONG_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_LONG_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      number ^= JreLShift64((jlong) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  else {
    for (jint i = 0; i < load_->size_ - loadOffset; i++) {
      number ^= JreLShift64((jlong) (IOSByteArray_Get(load_, loadOffset + i) & (jint) 0xFF), (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i));
    }
  }
  return number;
}

void LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store16WithByteArray_withInt_withShort_(IOSByteArray *store, jint storeOffset, jshort number) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  if (((IOSByteArray *) nil_chk(store))->size_ - storeOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_SHORT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_SHORT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift32(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jint) 0xFF);
    }
  }
  else {
    for (jint i = 0; i < store->size_ - storeOffset; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift32(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jint) 0xFF);
    }
  }
}

void LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store32WithByteArray_withInt_withInt_(IOSByteArray *store, jint storeOffset, jint number) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  if (((IOSByteArray *) nil_chk(store))->size_ - storeOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_INT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_INT_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift32(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jint) 0xFF);
    }
  }
  else {
    for (jint i = 0; i < store->size_ - storeOffset; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift32(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jint) 0xFF);
    }
  }
}

void LibOrgBouncycastlePqcCryptoQteslaCommonFunction_store64WithByteArray_withInt_withLong_(IOSByteArray *store, jint storeOffset, jlong number) {
  LibOrgBouncycastlePqcCryptoQteslaCommonFunction_initialize();
  if (((IOSByteArray *) nil_chk(store))->size_ - storeOffset >= LibOrgBouncycastlePqcCryptoQteslaConst_LONG_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE) {
    for (jint i = 0; i < LibOrgBouncycastlePqcCryptoQteslaConst_LONG_SIZE / LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift64(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jlong) 0xFFLL);
    }
  }
  else {
    for (jint i = 0; i < store->size_ - storeOffset; i++) {
      *IOSByteArray_GetRef(store, storeOffset + i) = (jbyte) ((JreRShift64(number, (LibOrgBouncycastlePqcCryptoQteslaConst_BC_BYTE_SIZE * i))) & (jlong) 0xFFLL);
    }
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoQteslaCommonFunction)