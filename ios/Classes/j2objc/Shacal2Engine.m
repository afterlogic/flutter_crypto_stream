//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/Shacal2Engine.java
//

#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OutputLengthException.h"
#include "Shacal2Engine.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleCryptoEnginesShacal2Engine () {
 @public
  jboolean forEncryption_;
  IOSIntArray *workingKey_;
}

- (void)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset;

- (void)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset;

- (void)byteBlockToIntsWithByteArray:(IOSByteArray *)bytes
                        withIntArray:(IOSIntArray *)block
                             withInt:(jint)bytesPos
                             withInt:(jint)blockPos;

- (void)bytes2intsWithByteArray:(IOSByteArray *)bytes
                   withIntArray:(IOSIntArray *)block
                        withInt:(jint)bytesPos
                        withInt:(jint)blockPos;

- (void)ints2bytesWithIntArray:(IOSIntArray *)block
                 withByteArray:(IOSByteArray *)outArg
                       withInt:(jint)pos;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesShacal2Engine, workingKey_, IOSIntArray *)

inline IOSIntArray *LibOrgBouncycastleCryptoEnginesShacal2Engine_get_K(void);
static IOSIntArray *LibOrgBouncycastleCryptoEnginesShacal2Engine_K;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesShacal2Engine, K, IOSIntArray *)

inline jint LibOrgBouncycastleCryptoEnginesShacal2Engine_get_BLOCK_SIZE(void);
#define LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesShacal2Engine, BLOCK_SIZE, jint)

inline jint LibOrgBouncycastleCryptoEnginesShacal2Engine_get_ROUNDS(void);
#define LibOrgBouncycastleCryptoEnginesShacal2Engine_ROUNDS 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesShacal2Engine, ROUNDS, jint)

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesShacal2Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *inArg, jint inOffset, IOSByteArray *outArg, jint outOffset);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesShacal2Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *inArg, jint inOffset, IOSByteArray *outArg, jint outOffset);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesShacal2Engine_byteBlockToIntsWithByteArray_withIntArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *bytes, IOSIntArray *block, jint bytesPos, jint blockPos);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesShacal2Engine_bytes2intsWithByteArray_withIntArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *bytes, IOSIntArray *block, jint bytesPos, jint blockPos);

__attribute__((unused)) static void LibOrgBouncycastleCryptoEnginesShacal2Engine_ints2bytesWithIntArray_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSIntArray *block, IOSByteArray *outArg, jint pos);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoEnginesShacal2Engine)

@implementation LibOrgBouncycastleCryptoEnginesShacal2Engine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)reset {
}

- (NSString *)getAlgorithmName {
  return @"Shacal2";
}

- (jint)getBlockSize {
  return LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE;
}

- (void)init__WithBoolean:(jboolean)_forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if (!([params isKindOfClass:[LibOrgBouncycastleCryptoParamsKeyParameter class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"only simple KeyParameter expected.");
  }
  self->forEncryption_ = _forEncryption;
  workingKey_ = [IOSIntArray newArrayWithLength:64];
  [self setKeyWithByteArray:[((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(((LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(params, [LibOrgBouncycastleCryptoParamsKeyParameter class])))) getKey]];
}

- (void)setKeyWithByteArray:(IOSByteArray *)kb {
  if (((IOSByteArray *) nil_chk(kb))->size_ == 0 || kb->size_ > 64 || kb->size_ < 16 || kb->size_ % 8 != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Shacal2-key must be 16 - 64 bytes and multiple of 8");
  }
  LibOrgBouncycastleCryptoEnginesShacal2Engine_bytes2intsWithByteArray_withIntArray_withInt_withInt_(self, kb, workingKey_, 0, 0);
  for (jint i = 16; i < 64; i++) {
    *IOSIntArray_GetRef(nil_chk(workingKey_), i) = (((JreURShift32(IOSIntArray_Get(workingKey_, i - 2), 17)) | (JreLShift32(IOSIntArray_Get(workingKey_, i - 2), -17))) ^ ((JreURShift32(IOSIntArray_Get(workingKey_, i - 2), 19)) | (JreLShift32(IOSIntArray_Get(workingKey_, i - 2), -19))) ^ (JreURShift32(IOSIntArray_Get(workingKey_, i - 2), 10))) + IOSIntArray_Get(workingKey_, i - 7) + (((JreURShift32(IOSIntArray_Get(workingKey_, i - 15), 7)) | (JreLShift32(IOSIntArray_Get(workingKey_, i - 15), -7))) ^ ((JreURShift32(IOSIntArray_Get(workingKey_, i - 15), 18)) | (JreLShift32(IOSIntArray_Get(workingKey_, i - 15), -18))) ^ (JreURShift32(IOSIntArray_Get(workingKey_, i - 15), 3))) + IOSIntArray_Get(workingKey_, i - 16);
  }
}

- (void)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOffset, outArg, outOffset);
}

- (void)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOffset, outArg, outOffset);
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOffset
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOffset {
  if (workingKey_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Shacal2 not initialised");
  }
  if ((inOffset + LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOffset + LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (forEncryption_) {
    LibOrgBouncycastleCryptoEnginesShacal2Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOffset, outArg, outOffset);
  }
  else {
    LibOrgBouncycastleCryptoEnginesShacal2Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOffset, outArg, outOffset);
  }
  return LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE;
}

- (void)byteBlockToIntsWithByteArray:(IOSByteArray *)bytes
                        withIntArray:(IOSIntArray *)block
                             withInt:(jint)bytesPos
                             withInt:(jint)blockPos {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_byteBlockToIntsWithByteArray_withIntArray_withInt_withInt_(self, bytes, block, bytesPos, blockPos);
}

- (void)bytes2intsWithByteArray:(IOSByteArray *)bytes
                   withIntArray:(IOSIntArray *)block
                        withInt:(jint)bytesPos
                        withInt:(jint)blockPos {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_bytes2intsWithByteArray_withIntArray_withInt_withInt_(self, bytes, block, bytesPos, blockPos);
}

- (void)ints2bytesWithIntArray:(IOSIntArray *)block
                 withByteArray:(IOSByteArray *)outArg
                       withInt:(jint)pos {
  LibOrgBouncycastleCryptoEnginesShacal2Engine_ints2bytesWithIntArray_withByteArray_withInt_(self, block, outArg, pos);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 7, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, 6, 9, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 12, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(reset);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[5].selector = @selector(setKeyWithByteArray:);
  methods[6].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[7].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[8].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[9].selector = @selector(byteBlockToIntsWithByteArray:withIntArray:withInt:withInt:);
  methods[10].selector = @selector(bytes2intsWithByteArray:withIntArray:withInt:withInt:);
  methods[11].selector = @selector(ints2bytesWithIntArray:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "K", "[I", .constantValue.asLong = 0, 0x1a, -1, 15, -1, -1 },
    { "BLOCK_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE, 0x1a, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ROUNDS", "I", .constantValue.asInt = LibOrgBouncycastleCryptoEnginesShacal2Engine_ROUNDS, 0x1a, -1, -1, -1, -1 },
    { "workingKey_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "setKey", "[B", "encryptBlock", "[BI[BI", "decryptBlock", "processBlock", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "byteBlockToInts", "[B[III", "bytes2ints", "ints2bytes", "[I[BI", &LibOrgBouncycastleCryptoEnginesShacal2Engine_K };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesShacal2Engine = { "Shacal2Engine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 12, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesShacal2Engine;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoEnginesShacal2Engine class]) {
    LibOrgBouncycastleCryptoEnginesShacal2Engine_K = [IOSIntArray newArrayWithInts:(jint[]){ (jint) 0x428a2f98, (jint) 0x71374491, (jint) 0xb5c0fbcf, (jint) 0xe9b5dba5, (jint) 0x3956c25b, (jint) 0x59f111f1, (jint) 0x923f82a4, (jint) 0xab1c5ed5, (jint) 0xd807aa98, (jint) 0x12835b01, (jint) 0x243185be, (jint) 0x550c7dc3, (jint) 0x72be5d74, (jint) 0x80deb1fe, (jint) 0x9bdc06a7, (jint) 0xc19bf174, (jint) 0xe49b69c1, (jint) 0xefbe4786, (jint) 0x0fc19dc6, (jint) 0x240ca1cc, (jint) 0x2de92c6f, (jint) 0x4a7484aa, (jint) 0x5cb0a9dc, (jint) 0x76f988da, (jint) 0x983e5152, (jint) 0xa831c66d, (jint) 0xb00327c8, (jint) 0xbf597fc7, (jint) 0xc6e00bf3, (jint) 0xd5a79147, (jint) 0x06ca6351, (jint) 0x14292967, (jint) 0x27b70a85, (jint) 0x2e1b2138, (jint) 0x4d2c6dfc, (jint) 0x53380d13, (jint) 0x650a7354, (jint) 0x766a0abb, (jint) 0x81c2c92e, (jint) 0x92722c85, (jint) 0xa2bfe8a1, (jint) 0xa81a664b, (jint) 0xc24b8b70, (jint) 0xc76c51a3, (jint) 0xd192e819, (jint) 0xd6990624, (jint) 0xf40e3585, (jint) 0x106aa070, (jint) 0x19a4c116, (jint) 0x1e376c08, (jint) 0x2748774c, (jint) 0x34b0bcb5, (jint) 0x391c0cb3, (jint) 0x4ed8aa4a, (jint) 0x5b9cca4f, (jint) 0x682e6ff3, (jint) 0x748f82ee, (jint) 0x78a5636f, (jint) 0x84c87814, (jint) 0x8cc70208, (jint) 0x90befffa, (jint) 0xa4506ceb, (jint) 0xbef9a3f7, (jint) 0xc67178f2 } count:64];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoEnginesShacal2Engine)
  }
}

@end

void LibOrgBouncycastleCryptoEnginesShacal2Engine_init(LibOrgBouncycastleCryptoEnginesShacal2Engine *self) {
  NSObject_init(self);
  self->forEncryption_ = false;
  self->workingKey_ = nil;
}

LibOrgBouncycastleCryptoEnginesShacal2Engine *new_LibOrgBouncycastleCryptoEnginesShacal2Engine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesShacal2Engine, init)
}

LibOrgBouncycastleCryptoEnginesShacal2Engine *create_LibOrgBouncycastleCryptoEnginesShacal2Engine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesShacal2Engine, init)
}

void LibOrgBouncycastleCryptoEnginesShacal2Engine_encryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *inArg, jint inOffset, IOSByteArray *outArg, jint outOffset) {
  IOSIntArray *block = [IOSIntArray newArrayWithLength:LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE / 4];
  LibOrgBouncycastleCryptoEnginesShacal2Engine_byteBlockToIntsWithByteArray_withIntArray_withInt_withInt_(self, inArg, block, inOffset, 0);
  for (jint i = 0; i < LibOrgBouncycastleCryptoEnginesShacal2Engine_ROUNDS; i++) {
    jint tmp = (((JreURShift32(IOSIntArray_Get(block, 4), 6)) | (JreLShift32(IOSIntArray_Get(block, 4), -6))) ^ ((JreURShift32(IOSIntArray_Get(block, 4), 11)) | (JreLShift32(IOSIntArray_Get(block, 4), -11))) ^ ((JreURShift32(IOSIntArray_Get(block, 4), 25)) | (JreLShift32(IOSIntArray_Get(block, 4), -25)))) + ((IOSIntArray_Get(block, 4) & IOSIntArray_Get(block, 5)) ^ ((~IOSIntArray_Get(block, 4)) & IOSIntArray_Get(block, 6))) + IOSIntArray_Get(block, 7) + IOSIntArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesShacal2Engine_K), i) + IOSIntArray_Get(nil_chk(self->workingKey_), i);
    *IOSIntArray_GetRef(block, 7) = IOSIntArray_Get(block, 6);
    *IOSIntArray_GetRef(block, 6) = IOSIntArray_Get(block, 5);
    *IOSIntArray_GetRef(block, 5) = IOSIntArray_Get(block, 4);
    *IOSIntArray_GetRef(block, 4) = IOSIntArray_Get(block, 3) + tmp;
    *IOSIntArray_GetRef(block, 3) = IOSIntArray_Get(block, 2);
    *IOSIntArray_GetRef(block, 2) = IOSIntArray_Get(block, 1);
    *IOSIntArray_GetRef(block, 1) = IOSIntArray_Get(block, 0);
    *IOSIntArray_GetRef(block, 0) = tmp + (((JreURShift32(IOSIntArray_Get(block, 0), 2)) | (JreLShift32(IOSIntArray_Get(block, 0), -2))) ^ ((JreURShift32(IOSIntArray_Get(block, 0), 13)) | (JreLShift32(IOSIntArray_Get(block, 0), -13))) ^ ((JreURShift32(IOSIntArray_Get(block, 0), 22)) | (JreLShift32(IOSIntArray_Get(block, 0), -22)))) + ((IOSIntArray_Get(block, 0) & IOSIntArray_Get(block, 2)) ^ (IOSIntArray_Get(block, 0) & IOSIntArray_Get(block, 3)) ^ (IOSIntArray_Get(block, 2) & IOSIntArray_Get(block, 3)));
  }
  LibOrgBouncycastleCryptoEnginesShacal2Engine_ints2bytesWithIntArray_withByteArray_withInt_(self, block, outArg, outOffset);
}

void LibOrgBouncycastleCryptoEnginesShacal2Engine_decryptBlockWithByteArray_withInt_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *inArg, jint inOffset, IOSByteArray *outArg, jint outOffset) {
  IOSIntArray *block = [IOSIntArray newArrayWithLength:LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE / 4];
  LibOrgBouncycastleCryptoEnginesShacal2Engine_byteBlockToIntsWithByteArray_withIntArray_withInt_withInt_(self, inArg, block, inOffset, 0);
  for (jint i = LibOrgBouncycastleCryptoEnginesShacal2Engine_ROUNDS - 1; i > -1; i--) {
    jint tmp = IOSIntArray_Get(block, 0) - (((JreURShift32(IOSIntArray_Get(block, 1), 2)) | (JreLShift32(IOSIntArray_Get(block, 1), -2))) ^ ((JreURShift32(IOSIntArray_Get(block, 1), 13)) | (JreLShift32(IOSIntArray_Get(block, 1), -13))) ^ ((JreURShift32(IOSIntArray_Get(block, 1), 22)) | (JreLShift32(IOSIntArray_Get(block, 1), -22)))) - ((IOSIntArray_Get(block, 1) & IOSIntArray_Get(block, 2)) ^ (IOSIntArray_Get(block, 1) & IOSIntArray_Get(block, 3)) ^ (IOSIntArray_Get(block, 2) & IOSIntArray_Get(block, 3)));
    *IOSIntArray_GetRef(block, 0) = IOSIntArray_Get(block, 1);
    *IOSIntArray_GetRef(block, 1) = IOSIntArray_Get(block, 2);
    *IOSIntArray_GetRef(block, 2) = IOSIntArray_Get(block, 3);
    *IOSIntArray_GetRef(block, 3) = IOSIntArray_Get(block, 4) - tmp;
    *IOSIntArray_GetRef(block, 4) = IOSIntArray_Get(block, 5);
    *IOSIntArray_GetRef(block, 5) = IOSIntArray_Get(block, 6);
    *IOSIntArray_GetRef(block, 6) = IOSIntArray_Get(block, 7);
    *IOSIntArray_GetRef(block, 7) = tmp - IOSIntArray_Get(nil_chk(LibOrgBouncycastleCryptoEnginesShacal2Engine_K), i) - IOSIntArray_Get(nil_chk(self->workingKey_), i) - (((JreURShift32(IOSIntArray_Get(block, 4), 6)) | (JreLShift32(IOSIntArray_Get(block, 4), -6))) ^ ((JreURShift32(IOSIntArray_Get(block, 4), 11)) | (JreLShift32(IOSIntArray_Get(block, 4), -11))) ^ ((JreURShift32(IOSIntArray_Get(block, 4), 25)) | (JreLShift32(IOSIntArray_Get(block, 4), -25)))) - ((IOSIntArray_Get(block, 4) & IOSIntArray_Get(block, 5)) ^ ((~IOSIntArray_Get(block, 4)) & IOSIntArray_Get(block, 6)));
  }
  LibOrgBouncycastleCryptoEnginesShacal2Engine_ints2bytesWithIntArray_withByteArray_withInt_(self, block, outArg, outOffset);
}

void LibOrgBouncycastleCryptoEnginesShacal2Engine_byteBlockToIntsWithByteArray_withIntArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *bytes, IOSIntArray *block, jint bytesPos, jint blockPos) {
  for (jint i = blockPos; i < LibOrgBouncycastleCryptoEnginesShacal2Engine_BLOCK_SIZE / 4; i++) {
    jint unseq$1 = bytesPos++;
    jint unseq$2 = bytesPos++;
    jint unseq$3 = bytesPos++;
    *IOSIntArray_GetRef(nil_chk(block), i) = (JreLShift32((IOSByteArray_Get(nil_chk(bytes), unseq$1) & (jint) 0xFF), 24)) | (JreLShift32((IOSByteArray_Get(bytes, unseq$2) & (jint) 0xFF), 16)) | (JreLShift32((IOSByteArray_Get(bytes, unseq$3) & (jint) 0xFF), 8)) | (IOSByteArray_Get(bytes, bytesPos++) & (jint) 0xFF);
  }
}

void LibOrgBouncycastleCryptoEnginesShacal2Engine_bytes2intsWithByteArray_withIntArray_withInt_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSByteArray *bytes, IOSIntArray *block, jint bytesPos, jint blockPos) {
  for (jint i = blockPos; i < ((IOSByteArray *) nil_chk(bytes))->size_ / 4; i++) {
    jint unseq$1 = bytesPos++;
    jint unseq$2 = bytesPos++;
    jint unseq$3 = bytesPos++;
    *IOSIntArray_GetRef(nil_chk(block), i) = (JreLShift32((IOSByteArray_Get(bytes, unseq$1) & (jint) 0xFF), 24)) | (JreLShift32((IOSByteArray_Get(bytes, unseq$2) & (jint) 0xFF), 16)) | (JreLShift32((IOSByteArray_Get(bytes, unseq$3) & (jint) 0xFF), 8)) | (IOSByteArray_Get(bytes, bytesPos++) & (jint) 0xFF);
  }
}

void LibOrgBouncycastleCryptoEnginesShacal2Engine_ints2bytesWithIntArray_withByteArray_withInt_(LibOrgBouncycastleCryptoEnginesShacal2Engine *self, IOSIntArray *block, IOSByteArray *outArg, jint pos) {
  for (jint i = 0; i < ((IOSIntArray *) nil_chk(block))->size_; i++) {
    *IOSByteArray_GetRef(nil_chk(outArg), pos++) = (jbyte) (JreURShift32(IOSIntArray_Get(block, i), 24));
    *IOSByteArray_GetRef(outArg, pos++) = (jbyte) (JreURShift32(IOSIntArray_Get(block, i), 16));
    *IOSByteArray_GetRef(outArg, pos++) = (jbyte) (JreURShift32(IOSIntArray_Get(block, i), 8));
    *IOSByteArray_GetRef(outArg, pos++) = (jbyte) IOSIntArray_Get(block, i);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesShacal2Engine)
