//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/KDFDoublePipelineIterationParameters.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KDFDoublePipelineIterationParameters.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters () {
 @public
  IOSByteArray *ki_;
  jboolean useCounter_;
  jint r_;
  IOSByteArray *fixedInputData_;
}

- (instancetype)initWithByteArray:(IOSByteArray *)ki
                    withByteArray:(IOSByteArray *)fixedInputData
                          withInt:(jint)r
                      withBoolean:(jboolean)useCounter;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters, ki_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters, fixedInputData_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_get_UNUSED_R(void);
#define LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_UNUSED_R 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters, UNUSED_R, jint)

__attribute__((unused)) static void LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *self, IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter);

__attribute__((unused)) static LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *new_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *create_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter);

@implementation LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters

- (instancetype)initWithByteArray:(IOSByteArray *)ki
                    withByteArray:(IOSByteArray *)fixedInputData
                          withInt:(jint)r
                      withBoolean:(jboolean)useCounter {
  LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(self, ki, fixedInputData, r, useCounter);
  return self;
}

+ (LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *)createWithCounterWithByteArray:(IOSByteArray *)ki
                                                                                         withByteArray:(IOSByteArray *)fixedInputData
                                                                                               withInt:(jint)r {
  return LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_createWithCounterWithByteArray_withByteArray_withInt_(ki, fixedInputData, r);
}

+ (LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *)createWithoutCounterWithByteArray:(IOSByteArray *)ki
                                                                                            withByteArray:(IOSByteArray *)fixedInputData {
  return LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_createWithoutCounterWithByteArray_withByteArray_(ki, fixedInputData);
}

- (IOSByteArray *)getKI {
  return ki_;
}

- (jboolean)useCounter {
  return useCounter_;
}

- (jint)getR {
  return r_;
}

- (IOSByteArray *)getFixedInputData {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withByteArray:withInt:withBoolean:);
  methods[1].selector = @selector(createWithCounterWithByteArray:withByteArray:withInt:);
  methods[2].selector = @selector(createWithoutCounterWithByteArray:withByteArray:);
  methods[3].selector = @selector(getKI);
  methods[4].selector = @selector(useCounter);
  methods[5].selector = @selector(getR);
  methods[6].selector = @selector(getFixedInputData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "UNUSED_R", "I", .constantValue.asInt = LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_UNUSED_R, 0x1a, -1, -1, -1, -1 },
    { "ki_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "useCounter_", "Z", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "r_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "fixedInputData_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B[BIZ", "createWithCounter", "[B[BI", "createWithoutCounter", "[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters = { "KDFDoublePipelineIterationParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x11, 7, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters;
}

@end

void LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *self, IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter) {
  NSObject_init(self);
  if (ki == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"A KDF requires Ki (a seed) as input");
  }
  self->ki_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(ki);
  if (fixedInputData == nil) {
    self->fixedInputData_ = [IOSByteArray newArrayWithLength:0];
  }
  else {
    self->fixedInputData_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(fixedInputData);
  }
  if (r != 8 && r != 16 && r != 24 && r != 32) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Length of counter should be 8, 16, 24 or 32");
  }
  self->r_ = r;
  self->useCounter_ = useCounter;
}

LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *new_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters, initWithByteArray_withByteArray_withInt_withBoolean_, ki, fixedInputData, r, useCounter)
}

LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *create_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(IOSByteArray *ki, IOSByteArray *fixedInputData, jint r, jboolean useCounter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters, initWithByteArray_withByteArray_withInt_withBoolean_, ki, fixedInputData, r, useCounter)
}

LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_createWithCounterWithByteArray_withByteArray_withInt_(IOSByteArray *ki, IOSByteArray *fixedInputData, jint r) {
  LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initialize();
  return new_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(ki, fixedInputData, r, true);
}

LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters *LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_createWithoutCounterWithByteArray_withByteArray_(IOSByteArray *ki, IOSByteArray *fixedInputData) {
  LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initialize();
  return new_LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_initWithByteArray_withByteArray_withInt_withBoolean_(ki, fixedInputData, LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters_UNUSED_R, false);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsKDFDoublePipelineIterationParameters)