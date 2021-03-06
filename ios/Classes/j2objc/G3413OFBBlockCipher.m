//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/G3413OFBBlockCipher.java
//

#include "Arrays.h"
#include "BlockCipher.h"
#include "CipherParameters.h"
#include "G3413OFBBlockCipher.h"
#include "GOST3413CipherUtil.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithIV.h"
#include "StreamBlockCipher.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoModesG3413OFBBlockCipher () {
 @public
  jint m_;
  jint blockSize_;
  IOSByteArray *R_;
  IOSByteArray *R_init_;
  IOSByteArray *Y_;
  id<LibOrgBouncycastleCryptoBlockCipher> cipher_G3413OFBBlockCipher_;
  jint byteCount_;
  jboolean initialized_;
}

- (void)initArrays OBJC_METHOD_FAMILY_NONE;

- (void)setupDefaultParams;

- (void)generateY;

- (void)generateR;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, R_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, R_init_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, Y_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, cipher_G3413OFBBlockCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initArrays(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_setupDefaultParams(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateY(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self);

__attribute__((unused)) static void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateR(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self);

@implementation LibOrgBouncycastleCryptoModesG3413OFBBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher {
  LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, cipher);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithIV *ivParam = (LibOrgBouncycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(ivParam)) getIV];
    if (((IOSByteArray *) nil_chk(iv))->size_ < blockSize_) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Parameter m must blockSize <= m");
    }
    self->m_ = iv->size_;
    LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initArrays(self);
    R_init_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(iv);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(R_init_, 0, R_, 0, ((IOSByteArray *) nil_chk(R_init_))->size_);
    if ([ivParam getParameters] != nil) {
      [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_G3413OFBBlockCipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:[ivParam getParameters]];
    }
  }
  else {
    LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_setupDefaultParams(self);
    LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initArrays(self);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(R_init_, 0, R_, 0, ((IOSByteArray *) nil_chk(R_init_))->size_);
    if (params != nil) {
      [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_G3413OFBBlockCipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:params];
    }
  }
  initialized_ = true;
}

- (void)initArrays {
  LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initArrays(self);
}

- (void)setupDefaultParams {
  LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_setupDefaultParams(self);
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_G3413OFBBlockCipher_)) getAlgorithmName], @"/OFB");
}

- (jint)getBlockSize {
  return blockSize_;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  [self processBytesWithByteArray:inArg withInt:inOff withInt:blockSize_ withByteArray:outArg withInt:outOff];
  return blockSize_;
}

- (jbyte)calculateByteWithByte:(jbyte)inArg {
  if (byteCount_ == 0) {
    LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateY(self);
  }
  jbyte rv = (jbyte) (IOSByteArray_Get(nil_chk(Y_), byteCount_) ^ inArg);
  byteCount_++;
  if (byteCount_ == [self getBlockSize]) {
    byteCount_ = 0;
    LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateR(self);
  }
  return rv;
}

- (void)generateY {
  LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateY(self);
}

- (void)generateR {
  LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateR(self);
}

- (void)reset {
  if (initialized_) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(R_init_, 0, R_, 0, ((IOSByteArray *) nil_chk(R_init_))->size_);
    LibOrgBouncycastleUtilArrays_clearWithByteArray_(Y_);
    byteCount_ = 0;
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher_G3413OFBBlockCipher_)) reset];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, 6, -1, -1, -1 },
    { NULL, "B", 0x4, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(initArrays);
  methods[3].selector = @selector(setupDefaultParams);
  methods[4].selector = @selector(getAlgorithmName);
  methods[5].selector = @selector(getBlockSize);
  methods[6].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[7].selector = @selector(calculateByteWithByte:);
  methods[8].selector = @selector(generateY);
  methods[9].selector = @selector(generateR);
  methods[10].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "m_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "R_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "R_init_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "Y_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_G3413OFBBlockCipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, 9, -1, -1, -1 },
    { "byteCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialized_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "processBlock", "[BI[BI", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "calculateByte", "B", "cipher" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesG3413OFBBlockCipher = { "G3413OFBBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 11, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesG3413OFBBlockCipher;
}

@end

void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  LibOrgBouncycastleCryptoStreamBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(self, cipher);
  self->initialized_ = false;
  self->blockSize_ = [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize];
  self->cipher_G3413OFBBlockCipher_ = cipher;
  self->Y_ = [IOSByteArray newArrayWithLength:self->blockSize_];
}

LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *new_LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, cipher)
}

LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *create_LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_, cipher)
}

void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_initArrays(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self) {
  self->R_ = [IOSByteArray newArrayWithLength:self->m_];
  self->R_init_ = [IOSByteArray newArrayWithLength:self->m_];
}

void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_setupDefaultParams(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self) {
  self->m_ = 2 * self->blockSize_;
}

void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateY(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self) {
  IOSByteArray *msb = LibOrgBouncycastleCryptoModesGOST3413CipherUtil_MSBWithByteArray_withInt_(self->R_, self->blockSize_);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(self->cipher_G3413OFBBlockCipher_)) processBlockWithByteArray:msb withInt:0 withByteArray:self->Y_ withInt:0];
}

void LibOrgBouncycastleCryptoModesG3413OFBBlockCipher_generateR(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher *self) {
  IOSByteArray *buf = LibOrgBouncycastleCryptoModesGOST3413CipherUtil_LSBWithByteArray_withInt_(self->R_, self->m_ - self->blockSize_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, 0, self->R_, 0, ((IOSByteArray *) nil_chk(buf))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->Y_, 0, self->R_, buf->size_, self->m_ - buf->size_);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesG3413OFBBlockCipher)
