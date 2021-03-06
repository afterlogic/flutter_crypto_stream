//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/DESedeParameters.java
//

#include "DESParameters.h"
#include "DESedeParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@implementation LibOrgBouncycastleCryptoParamsDESedeParameters

+ (jint)DES_EDE_KEY_LENGTH {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_DES_EDE_KEY_LENGTH;
}

- (instancetype)initWithByteArray:(IOSByteArray *)key {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initWithByteArray_(self, key);
  return self;
}

+ (jboolean)isWeakKeyWithByteArray:(IOSByteArray *)key
                           withInt:(jint)offset
                           withInt:(jint)length {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(key, offset, length);
}

+ (jboolean)isWeakKeyWithByteArray:(IOSByteArray *)key
                           withInt:(jint)offset {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_(key, offset);
}

+ (jboolean)isRealEDEKeyWithByteArray:(IOSByteArray *)key
                              withInt:(jint)offset {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isRealEDEKeyWithByteArray_withInt_(key, offset);
}

+ (jboolean)isReal2KeyWithByteArray:(IOSByteArray *)key
                            withInt:(jint)offset {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isReal2KeyWithByteArray_withInt_(key, offset);
}

+ (jboolean)isReal3KeyWithByteArray:(IOSByteArray *)key
                            withInt:(jint)offset {
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isReal3KeyWithByteArray_withInt_(key, offset);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 4, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 5, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 6, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(isWeakKeyWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(isWeakKeyWithByteArray:withInt:);
  methods[3].selector = @selector(isRealEDEKeyWithByteArray:withInt:);
  methods[4].selector = @selector(isReal2KeyWithByteArray:withInt:);
  methods[5].selector = @selector(isReal3KeyWithByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DES_EDE_KEY_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsDESedeParameters_DES_EDE_KEY_LENGTH, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "isWeakKey", "[BII", "[BI", "isRealEDEKey", "isReal2Key", "isReal3Key" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsDESedeParameters = { "DESedeParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsDESedeParameters;
}

@end

void LibOrgBouncycastleCryptoParamsDESedeParameters_initWithByteArray_(LibOrgBouncycastleCryptoParamsDESedeParameters *self, IOSByteArray *key) {
  LibOrgBouncycastleCryptoParamsDESParameters_initWithByteArray_(self, key);
  if (LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(key, 0, ((IOSByteArray *) nil_chk(key))->size_)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"attempt to create weak DESede key");
  }
}

LibOrgBouncycastleCryptoParamsDESedeParameters *new_LibOrgBouncycastleCryptoParamsDESedeParameters_initWithByteArray_(IOSByteArray *key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsDESedeParameters, initWithByteArray_, key)
}

LibOrgBouncycastleCryptoParamsDESedeParameters *create_LibOrgBouncycastleCryptoParamsDESedeParameters_initWithByteArray_(IOSByteArray *key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsDESedeParameters, initWithByteArray_, key)
}

jboolean LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(IOSByteArray *key, jint offset, jint length) {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initialize();
  for (jint i = offset; i < length; i += LibOrgBouncycastleCryptoParamsDESParameters_DES_KEY_LENGTH) {
    if (LibOrgBouncycastleCryptoParamsDESParameters_isWeakKeyWithByteArray_withInt_(key, i)) {
      return true;
    }
  }
  return false;
}

jboolean LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_(IOSByteArray *key, jint offset) {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initialize();
  return LibOrgBouncycastleCryptoParamsDESedeParameters_isWeakKeyWithByteArray_withInt_withInt_(key, offset, ((IOSByteArray *) nil_chk(key))->size_ - offset);
}

jboolean LibOrgBouncycastleCryptoParamsDESedeParameters_isRealEDEKeyWithByteArray_withInt_(IOSByteArray *key, jint offset) {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initialize();
  return ((IOSByteArray *) nil_chk(key))->size_ == 16 ? LibOrgBouncycastleCryptoParamsDESedeParameters_isReal2KeyWithByteArray_withInt_(key, offset) : LibOrgBouncycastleCryptoParamsDESedeParameters_isReal3KeyWithByteArray_withInt_(key, offset);
}

jboolean LibOrgBouncycastleCryptoParamsDESedeParameters_isReal2KeyWithByteArray_withInt_(IOSByteArray *key, jint offset) {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initialize();
  jboolean isValid = false;
  for (jint i = offset; i != offset + 8; i++) {
    if (IOSByteArray_Get(nil_chk(key), i) != IOSByteArray_Get(key, i + 8)) {
      isValid = true;
    }
  }
  return isValid;
}

jboolean LibOrgBouncycastleCryptoParamsDESedeParameters_isReal3KeyWithByteArray_withInt_(IOSByteArray *key, jint offset) {
  LibOrgBouncycastleCryptoParamsDESedeParameters_initialize();
  jboolean diff12 = false;
  jboolean diff13 = false;
  jboolean diff23 = false;
  for (jint i = offset; i != offset + 8; i++) {
    diff12 |= (IOSByteArray_Get(nil_chk(key), i) != IOSByteArray_Get(key, i + 8));
    diff13 |= (IOSByteArray_Get(key, i) != IOSByteArray_Get(key, i + 16));
    diff23 |= (IOSByteArray_Get(key, i + 8) != IOSByteArray_Get(key, i + 16));
  }
  return diff12 && diff13 && diff23;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsDESedeParameters)
