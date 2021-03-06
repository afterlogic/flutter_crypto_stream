//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/KCTRBlockCipher.java
//

#include "Arrays.h"
#include "BlockCipher.h"
#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KCTRBlockCipher.h"
#include "OutputLengthException.h"
#include "ParametersWithIV.h"
#include "StreamBlockCipher.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoModesKCTRBlockCipher () {
 @public
  IOSByteArray *iv_;
  IOSByteArray *ofbV_;
  IOSByteArray *ofbOutV_;
  jint byteCount_;
  jboolean initialised_;
  id<LibOrgBouncycastleCryptoBlockCipher> engine_;
}

- (void)incrementCounterAtWithInt:(jint)pos;

- (void)checkCounter;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKCTRBlockCipher, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKCTRBlockCipher, ofbV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKCTRBlockCipher, ofbOutV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesKCTRBlockCipher, engine_, id<LibOrgBouncycastleCryptoBlockCipher>)

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(LibOrgBouncycastleCryptoModesKCTRBlockCipher *self, jint pos);

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesKCTRBlockCipher_checkCounter(LibOrgBouncycastleCryptoModesKCTRBlockCipher *self);

@implementation LibOrgBouncycastleCryptoModesKCTRBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)engine {
  LibOrgBouncycastleCryptoModesKCTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, engine);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  self->initialised_ = true;
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithIV *ivParam = (LibOrgBouncycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(ivParam)) getIV];
    jint diff = ((IOSByteArray *) nil_chk(self->iv_))->size_ - ((IOSByteArray *) nil_chk(iv))->size_;
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(self->iv_, (jbyte) 0);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, diff, iv->size_);
    params = [ivParam getParameters];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid parameter passed");
  }
  if (params != nil) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:params];
  }
  [self reset];
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) getAlgorithmName], @"/KCTR");
}

- (jint)getBlockSize {
  return [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize];
}

- (jbyte)calculateByteWithByte:(jbyte)b {
  if (byteCount_ == 0) {
    LibOrgBouncycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(self, 0);
    LibOrgBouncycastleCryptoModesKCTRBlockCipher_checkCounter(self);
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:ofbV_ withInt:0 withByteArray:ofbOutV_ withInt:0];
    return (jbyte) (IOSByteArray_Get(nil_chk(ofbOutV_), byteCount_++) ^ b);
  }
  jbyte rv = (jbyte) (IOSByteArray_Get(nil_chk(ofbOutV_), byteCount_++) ^ b);
  if (byteCount_ == ((IOSByteArray *) nil_chk(ofbV_))->size_) {
    byteCount_ = 0;
  }
  return rv;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (((IOSByteArray *) nil_chk(inArg))->size_ - inOff < [self getBlockSize]) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if (((IOSByteArray *) nil_chk(outArg))->size_ - outOff < [self getBlockSize]) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  [self processBytesWithByteArray:inArg withInt:inOff withInt:[self getBlockSize] withByteArray:outArg withInt:outOff];
  return [self getBlockSize];
}

- (void)reset {
  if (initialised_) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:self->iv_ withInt:0 withByteArray:ofbV_ withInt:0];
  }
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine_)) reset];
  byteCount_ = 0;
}

- (void)incrementCounterAtWithInt:(jint)pos {
  LibOrgBouncycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(self, pos);
}

- (void)checkCounter {
  LibOrgBouncycastleCryptoModesKCTRBlockCipher_checkCounter(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(calculateByteWithByte:);
  methods[5].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(incrementCounterAtWithInt:);
  methods[8].selector = @selector(checkCounter);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ofbV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ofbOutV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "engine_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "calculateByte", "B", "processBlock", "[BI[BI", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "incrementCounterAt", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesKCTRBlockCipher = { "KCTRBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 9, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesKCTRBlockCipher;
}

@end

void LibOrgBouncycastleCryptoModesKCTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesKCTRBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  LibOrgBouncycastleCryptoStreamBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, engine);
  self->engine_ = engine;
  self->iv_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize]];
  self->ofbV_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
  self->ofbOutV_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
}

LibOrgBouncycastleCryptoModesKCTRBlockCipher *new_LibOrgBouncycastleCryptoModesKCTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesKCTRBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, engine)
}

LibOrgBouncycastleCryptoModesKCTRBlockCipher *create_LibOrgBouncycastleCryptoModesKCTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesKCTRBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, engine)
}

void LibOrgBouncycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(LibOrgBouncycastleCryptoModesKCTRBlockCipher *self, jint pos) {
  jint i = pos;
  while (i < ((IOSByteArray *) nil_chk(self->ofbV_))->size_) {
    if (++(*IOSByteArray_GetRef(self->ofbV_, i++)) != 0) {
      break;
    }
  }
}

void LibOrgBouncycastleCryptoModesKCTRBlockCipher_checkCounter(LibOrgBouncycastleCryptoModesKCTRBlockCipher *self) {
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesKCTRBlockCipher)
