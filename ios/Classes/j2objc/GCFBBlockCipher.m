//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/GCFBBlockCipher.java
//

#include "BlockCipher.h"
#include "CFBBlockCipher.h"
#include "CipherParameters.h"
#include "GCFBBlockCipher.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "ParametersWithIV.h"
#include "ParametersWithRandom.h"
#include "ParametersWithSBox.h"
#include "StreamBlockCipher.h"

@interface LibOrgBouncycastleCryptoModesGCFBBlockCipher () {
 @public
  LibOrgBouncycastleCryptoModesCFBBlockCipher *cfbEngine_;
  LibOrgBouncycastleCryptoParamsKeyParameter *key_;
  jlong counter_;
  jboolean forEncryption_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesGCFBBlockCipher, cfbEngine_, LibOrgBouncycastleCryptoModesCFBBlockCipher *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesGCFBBlockCipher, key_, LibOrgBouncycastleCryptoParamsKeyParameter *)

inline IOSByteArray *LibOrgBouncycastleCryptoModesGCFBBlockCipher_get_C(void);
static IOSByteArray *LibOrgBouncycastleCryptoModesGCFBBlockCipher_C;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoModesGCFBBlockCipher, C, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoModesGCFBBlockCipher)

@implementation LibOrgBouncycastleCryptoModesGCFBBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)engine {
  LibOrgBouncycastleCryptoModesGCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, engine);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  counter_ = 0;
  [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) init__WithBoolean:forEncryption withLibOrgBouncycastleCryptoCipherParameters:params];
  self->forEncryption_ = forEncryption;
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    params = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithIV *) params))) getParameters];
  }
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    params = [((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithRandom *) params))) getParameters];
  }
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithSBox class]]) {
    params = [((LibOrgBouncycastleCryptoParamsParametersWithSBox *) nil_chk(((LibOrgBouncycastleCryptoParamsParametersWithSBox *) params))) getParameters];
  }
  key_ = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(params, [LibOrgBouncycastleCryptoParamsKeyParameter class]);
}

- (NSString *)getAlgorithmName {
  NSString *name = [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) getAlgorithmName];
  return JreStrcat("$$$", [((NSString *) nil_chk(name)) java_substring:0 endIndex:[name java_indexOf:'/']], @"/G", [name java_substring:[name java_indexOf:'/'] + 1]);
}

- (jint)getBlockSize {
  return [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) getBlockSize];
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  [self processBytesWithByteArray:inArg withInt:inOff withInt:[((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) getBlockSize] withByteArray:outArg withInt:outOff];
  return [cfbEngine_ getBlockSize];
}

- (jbyte)calculateByteWithByte:(jbyte)b {
  if (counter_ > 0 && counter_ % 1024 == 0) {
    id<LibOrgBouncycastleCryptoBlockCipher> base = [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) getUnderlyingCipher];
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(base)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:key_];
    IOSByteArray *nextKey = [IOSByteArray newArrayWithLength:32];
    [base processBlockWithByteArray:LibOrgBouncycastleCryptoModesGCFBBlockCipher_C withInt:0 withByteArray:nextKey withInt:0];
    [base processBlockWithByteArray:LibOrgBouncycastleCryptoModesGCFBBlockCipher_C withInt:8 withByteArray:nextKey withInt:8];
    [base processBlockWithByteArray:LibOrgBouncycastleCryptoModesGCFBBlockCipher_C withInt:16 withByteArray:nextKey withInt:16];
    [base processBlockWithByteArray:LibOrgBouncycastleCryptoModesGCFBBlockCipher_C withInt:24 withByteArray:nextKey withInt:24];
    key_ = new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(nextKey);
    [base init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:key_];
    IOSByteArray *iv = [cfbEngine_ getCurrentIV];
    [base processBlockWithByteArray:iv withInt:0 withByteArray:iv withInt:0];
    [cfbEngine_ init__WithBoolean:forEncryption_ withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(key_, iv)];
  }
  counter_++;
  return [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) calculateByteWithByte:b];
}

- (void)reset {
  counter_ = 0;
  [((LibOrgBouncycastleCryptoModesCFBBlockCipher *) nil_chk(cfbEngine_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, 6, -1, -1, -1 },
    { NULL, "B", 0x4, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(calculateByteWithByte:);
  methods[6].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "C", "[B", .constantValue.asLong = 0, 0x1a, -1, 9, -1, -1 },
    { "cfbEngine_", "LLibOrgBouncycastleCryptoModesCFBBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "key_", "LLibOrgBouncycastleCryptoParamsKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "counter_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "processBlock", "[BI[BI", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "calculateByte", "B", &LibOrgBouncycastleCryptoModesGCFBBlockCipher_C };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesGCFBBlockCipher = { "GCFBBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 7, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesGCFBBlockCipher;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoModesGCFBBlockCipher class]) {
    LibOrgBouncycastleCryptoModesGCFBBlockCipher_C = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jint) 0x69, (jint) 0x00, (jint) 0x72, (jint) 0x22, (jint) 0x64, (jbyte) (jint) 0xC9, (jint) 0x04, (jint) 0x23, (jbyte) (jint) 0x8D, (jint) 0x3A, (jbyte) (jint) 0xDB, (jbyte) (jint) 0x96, (jint) 0x46, (jbyte) (jint) 0xE9, (jint) 0x2A, (jbyte) (jint) 0xC4, (jint) 0x18, (jbyte) (jint) 0xFE, (jbyte) (jint) 0xAC, (jbyte) (jint) 0x94, (jint) 0x00, (jbyte) (jint) 0xED, (jint) 0x07, (jint) 0x12, (jbyte) (jint) 0xC0, (jbyte) (jint) 0x86, (jbyte) (jint) 0xDC, (jbyte) (jint) 0xC2, (jbyte) (jint) 0xEF, (jint) 0x4C, (jbyte) (jint) 0xA9, (jint) 0x2B } count:32];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoModesGCFBBlockCipher)
  }
}

@end

void LibOrgBouncycastleCryptoModesGCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesGCFBBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  LibOrgBouncycastleCryptoStreamBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, engine);
  self->counter_ = 0;
  self->cfbEngine_ = new_LibOrgBouncycastleCryptoModesCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(engine, [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize] * 8);
}

LibOrgBouncycastleCryptoModesGCFBBlockCipher *new_LibOrgBouncycastleCryptoModesGCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesGCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, engine)
}

LibOrgBouncycastleCryptoModesGCFBBlockCipher *create_LibOrgBouncycastleCryptoModesGCFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesGCFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, engine)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesGCFBBlockCipher)
