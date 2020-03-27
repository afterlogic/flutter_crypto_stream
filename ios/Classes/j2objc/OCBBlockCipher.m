//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/OCBBlockCipher.java
//

#include "AEADParameters.h"
#include "Arrays.h"
#include "BlockCipher.h"
#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "OCBBlockCipher.h"
#include "OutputLengthException.h"
#include "ParametersWithIV.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleCryptoModesOCBBlockCipher () {
 @public
  id<LibOrgBouncycastleCryptoBlockCipher> hashCipher_;
  id<LibOrgBouncycastleCryptoBlockCipher> mainCipher_;
  jboolean forEncryption_;
  jint macSize_;
  IOSByteArray *initialAssociatedText_;
  JavaUtilVector *L_;
  IOSByteArray *L_Asterisk_;
  IOSByteArray *L_Dollar_;
  IOSByteArray *KtopInput_;
  IOSByteArray *Stretch_;
  IOSByteArray *OffsetMAIN_0_;
  IOSByteArray *hashBlock_;
  IOSByteArray *mainBlock_;
  jint hashBlockPos_;
  jint mainBlockPos_;
  jlong hashBlockCount_;
  jlong mainBlockCount_;
  IOSByteArray *OffsetHASH_;
  IOSByteArray *Sum_;
  IOSByteArray *OffsetMAIN_;
  IOSByteArray *Checksum_;
  IOSByteArray *macBlock_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, hashCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, mainCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, initialAssociatedText_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, L_, JavaUtilVector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, L_Asterisk_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, L_Dollar_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, KtopInput_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, Stretch_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, OffsetMAIN_0_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, hashBlock_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, mainBlock_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, OffsetHASH_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, Sum_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, OffsetMAIN_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, Checksum_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoModesOCBBlockCipher, macBlock_, IOSByteArray *)

inline jint LibOrgBouncycastleCryptoModesOCBBlockCipher_get_BLOCK_SIZE(void);
#define LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoModesOCBBlockCipher, BLOCK_SIZE, jint)

@implementation LibOrgBouncycastleCryptoModesOCBBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)hashCipher
                    withLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)mainCipher {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_(self, hashCipher, mainCipher);
  return self;
}

- (id<LibOrgBouncycastleCryptoBlockCipher>)getUnderlyingCipher {
  return mainCipher_;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(mainCipher_)) getAlgorithmName], @"/OCB");
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  jboolean oldForEncryption = self->forEncryption_;
  self->forEncryption_ = forEncryption;
  self->macBlock_ = nil;
  LibOrgBouncycastleCryptoParamsKeyParameter *keyParameter;
  IOSByteArray *N;
  if ([parameters isKindOfClass:[LibOrgBouncycastleCryptoParamsAEADParameters class]]) {
    LibOrgBouncycastleCryptoParamsAEADParameters *aeadParameters = (LibOrgBouncycastleCryptoParamsAEADParameters *) parameters;
    N = [((LibOrgBouncycastleCryptoParamsAEADParameters *) nil_chk(aeadParameters)) getNonce];
    initialAssociatedText_ = [aeadParameters getAssociatedText];
    jint macSizeBits = [aeadParameters getMacSize];
    if (macSizeBits < 64 || macSizeBits > 128 || macSizeBits % 8 != 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Invalid value for MAC size: ", macSizeBits));
    }
    macSize_ = macSizeBits / 8;
    keyParameter = [aeadParameters getKey];
  }
  else if ([parameters isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithIV *parametersWithIV = (LibOrgBouncycastleCryptoParamsParametersWithIV *) parameters;
    N = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(parametersWithIV)) getIV];
    initialAssociatedText_ = nil;
    macSize_ = 16;
    keyParameter = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([parametersWithIV getParameters], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid parameters passed to OCB");
  }
  self->hashBlock_ = [IOSByteArray newArrayWithLength:16];
  self->mainBlock_ = [IOSByteArray newArrayWithLength:forEncryption ? LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE : (LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE + macSize_)];
  if (N == nil) {
    N = [IOSByteArray newArrayWithLength:0];
  }
  if (N->size_ > 15) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"IV must be no more than 15 bytes");
  }
  if (keyParameter != nil) {
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:keyParameter];
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(mainCipher_)) init__WithBoolean:forEncryption withLibOrgBouncycastleCryptoCipherParameters:keyParameter];
    KtopInput_ = nil;
  }
  else if (oldForEncryption != forEncryption) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"cannot change encrypting state without providing key.");
  }
  self->L_Asterisk_ = [IOSByteArray newArrayWithLength:16];
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) processBlockWithByteArray:L_Asterisk_ withInt:0 withByteArray:L_Asterisk_ withInt:0];
  self->L_Dollar_ = LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_doubleWithByteArray_(L_Asterisk_);
  self->L_ = new_JavaUtilVector_init();
  [self->L_ addElementWithId:LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_doubleWithByteArray_(L_Dollar_)];
  jint bottom = [self processNonceWithByteArray:N];
  jint bits = bottom % 8;
  jint bytes = bottom / 8;
  if (bits == 0) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(Stretch_, bytes, OffsetMAIN_0_, 0, 16);
  }
  else {
    for (jint i = 0; i < 16; ++i) {
      jint b1 = IOSByteArray_Get(nil_chk(Stretch_), bytes) & (jint) 0xff;
      jint b2 = IOSByteArray_Get(Stretch_, ++bytes) & (jint) 0xff;
      *IOSByteArray_GetRef(nil_chk(self->OffsetMAIN_0_), i) = (jbyte) ((JreLShift32(b1, bits)) | (JreURShift32(b2, (8 - bits))));
    }
  }
  self->hashBlockPos_ = 0;
  self->mainBlockPos_ = 0;
  self->hashBlockCount_ = 0;
  self->mainBlockCount_ = 0;
  self->OffsetHASH_ = [IOSByteArray newArrayWithLength:16];
  self->Sum_ = [IOSByteArray newArrayWithLength:16];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->OffsetMAIN_0_, 0, self->OffsetMAIN_, 0, 16);
  self->Checksum_ = [IOSByteArray newArrayWithLength:16];
  if (initialAssociatedText_ != nil) {
    [self processAADBytesWithByteArray:initialAssociatedText_ withInt:0 withInt:initialAssociatedText_->size_];
  }
}

- (jint)processNonceWithByteArray:(IOSByteArray *)N {
  IOSByteArray *nonce = [IOSByteArray newArrayWithLength:16];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(N, 0, nonce, nonce->size_ - ((IOSByteArray *) nil_chk(N))->size_, N->size_);
  *IOSByteArray_GetRef(nonce, 0) = (jbyte) (JreLShift32(macSize_, 4));
  *IOSByteArray_GetRef(nonce, 15 - N->size_) |= 1;
  jint bottom = IOSByteArray_Get(nonce, 15) & (jint) 0x3F;
  *IOSByteArray_GetRef(nonce, 15) &= (jint) 0xC0;
  if (KtopInput_ == nil || !LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(nonce, KtopInput_)) {
    IOSByteArray *Ktop = [IOSByteArray newArrayWithLength:16];
    KtopInput_ = nonce;
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) processBlockWithByteArray:KtopInput_ withInt:0 withByteArray:Ktop withInt:0];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(Ktop, 0, Stretch_, 0, 16);
    for (jint i = 0; i < 8; ++i) {
      *IOSByteArray_GetRef(nil_chk(Stretch_), 16 + i) = (jbyte) (IOSByteArray_Get(Ktop, i) ^ IOSByteArray_Get(Ktop, i + 1));
    }
  }
  return bottom;
}

- (IOSByteArray *)getMac {
  if (macBlock_ == nil) {
    return [IOSByteArray newArrayWithLength:macSize_];
  }
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(macBlock_);
}

- (jint)getOutputSizeWithInt:(jint)len {
  jint totalData = len + mainBlockPos_;
  if (forEncryption_) {
    return totalData + macSize_;
  }
  return totalData < macSize_ ? 0 : totalData - macSize_;
}

- (jint)getUpdateOutputSizeWithInt:(jint)len {
  jint totalData = len + mainBlockPos_;
  if (!forEncryption_) {
    if (totalData < macSize_) {
      return 0;
    }
    totalData -= macSize_;
  }
  return totalData - totalData % LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE;
}

- (void)processAADByteWithByte:(jbyte)input {
  *IOSByteArray_GetRef(nil_chk(hashBlock_), hashBlockPos_) = input;
  if (++hashBlockPos_ == hashBlock_->size_) {
    [self processHashBlock];
  }
}

- (void)processAADBytesWithByteArray:(IOSByteArray *)input
                             withInt:(jint)off
                             withInt:(jint)len {
  for (jint i = 0; i < len; ++i) {
    *IOSByteArray_GetRef(nil_chk(hashBlock_), hashBlockPos_) = IOSByteArray_Get(nil_chk(input), off + i);
    if (++hashBlockPos_ == hashBlock_->size_) {
      [self processHashBlock];
    }
  }
}

- (jint)processByteWithByte:(jbyte)input
              withByteArray:(IOSByteArray *)output
                    withInt:(jint)outOff {
  *IOSByteArray_GetRef(nil_chk(mainBlock_), mainBlockPos_) = input;
  if (++mainBlockPos_ == mainBlock_->size_) {
    [self processMainBlockWithByteArray:output withInt:outOff];
    return LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE;
  }
  return 0;
}

- (jint)processBytesWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff {
  if (((IOSByteArray *) nil_chk(input))->size_ < (inOff + len)) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"Input buffer too short");
  }
  jint resultLen = 0;
  for (jint i = 0; i < len; ++i) {
    *IOSByteArray_GetRef(nil_chk(mainBlock_), mainBlockPos_) = IOSByteArray_Get(input, inOff + i);
    if (++mainBlockPos_ == mainBlock_->size_) {
      [self processMainBlockWithByteArray:output withInt:outOff + resultLen];
      resultLen += LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE;
    }
  }
  return resultLen;
}

- (jint)doFinalWithByteArray:(IOSByteArray *)output
                     withInt:(jint)outOff {
  IOSByteArray *tag = nil;
  if (!forEncryption_) {
    if (mainBlockPos_ < macSize_) {
      @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"data too short");
    }
    mainBlockPos_ -= macSize_;
    tag = [IOSByteArray newArrayWithLength:macSize_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mainBlock_, mainBlockPos_, tag, 0, macSize_);
  }
  if (hashBlockPos_ > 0) {
    LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_extendWithByteArray_withInt_(hashBlock_, hashBlockPos_);
    [self updateHASHWithByteArray:L_Asterisk_];
  }
  if (mainBlockPos_ > 0) {
    if (forEncryption_) {
      LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_extendWithByteArray_withInt_(mainBlock_, mainBlockPos_);
      LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, mainBlock_);
    }
    LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(OffsetMAIN_, L_Asterisk_);
    IOSByteArray *Pad = [IOSByteArray newArrayWithLength:16];
    [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) processBlockWithByteArray:OffsetMAIN_ withInt:0 withByteArray:Pad withInt:0];
    LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(mainBlock_, Pad);
    if (((IOSByteArray *) nil_chk(output))->size_ < (outOff + mainBlockPos_)) {
      @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"Output buffer too short");
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mainBlock_, 0, output, outOff, mainBlockPos_);
    if (!forEncryption_) {
      LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_extendWithByteArray_withInt_(mainBlock_, mainBlockPos_);
      LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, mainBlock_);
    }
  }
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, OffsetMAIN_);
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, L_Dollar_);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) processBlockWithByteArray:Checksum_ withInt:0 withByteArray:Checksum_ withInt:0];
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, Sum_);
  self->macBlock_ = [IOSByteArray newArrayWithLength:macSize_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(Checksum_, 0, macBlock_, 0, macSize_);
  jint resultLen = mainBlockPos_;
  if (forEncryption_) {
    if (((IOSByteArray *) nil_chk(output))->size_ < (outOff + resultLen + macSize_)) {
      @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"Output buffer too short");
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(macBlock_, 0, output, outOff + resultLen, macSize_);
    resultLen += macSize_;
  }
  else {
    if (!LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(macBlock_, tag)) {
      @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"mac check in OCB failed");
    }
  }
  [self resetWithBoolean:false];
  return resultLen;
}

- (void)reset {
  [self resetWithBoolean:true];
}

- (void)clearWithByteArray:(IOSByteArray *)bs {
  if (bs != nil) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(bs, (jbyte) 0);
  }
}

- (IOSByteArray *)getLSubWithInt:(jint)n {
  while (n >= [((JavaUtilVector *) nil_chk(L_)) size]) {
    [((JavaUtilVector *) nil_chk(L_)) addElementWithId:LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_doubleWithByteArray_((IOSByteArray *) cast_chk([L_ lastElement], [IOSByteArray class]))];
  }
  return (IOSByteArray *) cast_chk([((JavaUtilVector *) nil_chk(L_)) elementAtWithInt:n], [IOSByteArray class]);
}

- (void)processHashBlock {
  [self updateHASHWithByteArray:[self getLSubWithInt:LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_ntzWithLong_(++hashBlockCount_)]];
  hashBlockPos_ = 0;
}

- (void)processMainBlockWithByteArray:(IOSByteArray *)output
                              withInt:(jint)outOff {
  if (((IOSByteArray *) nil_chk(output))->size_ < (outOff + LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE)) {
    @throw new_LibOrgBouncycastleCryptoOutputLengthException_initWithNSString_(@"Output buffer too short");
  }
  if (forEncryption_) {
    LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, mainBlock_);
    mainBlockPos_ = 0;
  }
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(OffsetMAIN_, [self getLSubWithInt:LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_ntzWithLong_(++mainBlockCount_)]);
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(mainBlock_, OffsetMAIN_);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(mainCipher_)) processBlockWithByteArray:mainBlock_ withInt:0 withByteArray:mainBlock_ withInt:0];
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(mainBlock_, OffsetMAIN_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mainBlock_, 0, output, outOff, 16);
  if (!forEncryption_) {
    LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Checksum_, mainBlock_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mainBlock_, LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE, mainBlock_, 0, macSize_);
    mainBlockPos_ = macSize_;
  }
}

- (void)resetWithBoolean:(jboolean)clearMac {
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) reset];
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(mainCipher_)) reset];
  [self clearWithByteArray:hashBlock_];
  [self clearWithByteArray:mainBlock_];
  hashBlockPos_ = 0;
  mainBlockPos_ = 0;
  hashBlockCount_ = 0;
  mainBlockCount_ = 0;
  [self clearWithByteArray:OffsetHASH_];
  [self clearWithByteArray:Sum_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(OffsetMAIN_0_, 0, OffsetMAIN_, 0, 16);
  [self clearWithByteArray:Checksum_];
  if (clearMac) {
    macBlock_ = nil;
  }
  if (initialAssociatedText_ != nil) {
    [self processAADBytesWithByteArray:initialAssociatedText_ withInt:0 withInt:initialAssociatedText_->size_];
  }
}

- (void)updateHASHWithByteArray:(IOSByteArray *)LSub {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(OffsetHASH_, LSub);
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(hashBlock_, OffsetHASH_);
  [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(hashCipher_)) processBlockWithByteArray:hashBlock_ withInt:0 withByteArray:hashBlock_ withInt:0];
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(Sum_, hashBlock_);
}

+ (IOSByteArray *)OCB_doubleWithByteArray:(IOSByteArray *)block {
  return LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_doubleWithByteArray_(block);
}

+ (void)OCB_extendWithByteArray:(IOSByteArray *)block
                        withInt:(jint)pos {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_extendWithByteArray_withInt_(block, pos);
}

+ (jint)OCB_ntzWithLong:(jlong)x {
  return LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_ntzWithLong_(x);
}

+ (jint)shiftLeftWithByteArray:(IOSByteArray *)block
                 withByteArray:(IOSByteArray *)output {
  return LibOrgBouncycastleCryptoModesOCBBlockCipher_shiftLeftWithByteArray_withByteArray_(block, output);
}

+ (void)xor__WithByteArray:(IOSByteArray *)block
             withByteArray:(IOSByteArray *)val {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(block, val);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 12, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 13, 14, 15, -1, -1, -1 },
    { NULL, "I", 0x1, 16, 17, 15, -1, -1, -1 },
    { NULL, "I", 0x1, 18, 19, 20, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 21, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 22, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 23, 19, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 24, 25, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 26, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0xc, 27, 5, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 28, 19, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 29, 30, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 31, 32, -1, -1, -1, -1 },
    { NULL, "V", 0xc, 33, 32, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBlockCipher:withLibOrgBouncycastleCryptoBlockCipher:);
  methods[1].selector = @selector(getUnderlyingCipher);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(processNonceWithByteArray:);
  methods[5].selector = @selector(getMac);
  methods[6].selector = @selector(getOutputSizeWithInt:);
  methods[7].selector = @selector(getUpdateOutputSizeWithInt:);
  methods[8].selector = @selector(processAADByteWithByte:);
  methods[9].selector = @selector(processAADBytesWithByteArray:withInt:withInt:);
  methods[10].selector = @selector(processByteWithByte:withByteArray:withInt:);
  methods[11].selector = @selector(processBytesWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[12].selector = @selector(doFinalWithByteArray:withInt:);
  methods[13].selector = @selector(reset);
  methods[14].selector = @selector(clearWithByteArray:);
  methods[15].selector = @selector(getLSubWithInt:);
  methods[16].selector = @selector(processHashBlock);
  methods[17].selector = @selector(processMainBlockWithByteArray:withInt:);
  methods[18].selector = @selector(resetWithBoolean:);
  methods[19].selector = @selector(updateHASHWithByteArray:);
  methods[20].selector = @selector(OCB_doubleWithByteArray:);
  methods[21].selector = @selector(OCB_extendWithByteArray:withInt:);
  methods[22].selector = @selector(OCB_ntzWithLong:);
  methods[23].selector = @selector(shiftLeftWithByteArray:withByteArray:);
  methods[24].selector = @selector(xor__WithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BLOCK_SIZE", "I", .constantValue.asInt = LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE, 0x1a, -1, -1, -1, -1 },
    { "hashCipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mainCipher_", "LLibOrgBouncycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "macSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialAssociatedText_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "L_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "L_Asterisk_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "L_Dollar_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "KtopInput_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "Stretch_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "OffsetMAIN_0_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashBlock_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mainBlock_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashBlockPos_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mainBlockPos_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashBlockCount_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mainBlockCount_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "OffsetHASH_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "Sum_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "OffsetMAIN_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "Checksum_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "macBlock_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBlockCipher;LLibOrgBouncycastleCryptoBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "processNonce", "[B", "getOutputSize", "I", "getUpdateOutputSize", "processAADByte", "B", "processAADBytes", "[BII", "processByte", "B[BI", "LLibOrgBouncycastleCryptoDataLengthException;", "processBytes", "[BII[BI", "doFinal", "[BI", "LJavaLangIllegalStateException;LLibOrgBouncycastleCryptoInvalidCipherTextException;", "clear", "getLSub", "processMainBlock", "reset", "Z", "updateHASH", "OCB_double", "OCB_extend", "OCB_ntz", "J", "shiftLeft", "[B[B", "xor" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoModesOCBBlockCipher = { "OCBBlockCipher", "lib.org.bouncycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 25, 23, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoModesOCBBlockCipher;
}

@end

void LibOrgBouncycastleCryptoModesOCBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesOCBBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> hashCipher, id<LibOrgBouncycastleCryptoBlockCipher> mainCipher) {
  NSObject_init(self);
  self->KtopInput_ = nil;
  self->Stretch_ = [IOSByteArray newArrayWithLength:24];
  self->OffsetMAIN_0_ = [IOSByteArray newArrayWithLength:16];
  self->OffsetMAIN_ = [IOSByteArray newArrayWithLength:16];
  if (hashCipher == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'hashCipher' cannot be null");
  }
  if ([hashCipher getBlockSize] != LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"'hashCipher' must have a block size of ", LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE));
  }
  if (mainCipher == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'mainCipher' cannot be null");
  }
  if ([mainCipher getBlockSize] != LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"'mainCipher' must have a block size of ", LibOrgBouncycastleCryptoModesOCBBlockCipher_BLOCK_SIZE));
  }
  if (![((NSString *) nil_chk([hashCipher getAlgorithmName])) isEqual:[mainCipher getAlgorithmName]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'hashCipher' and 'mainCipher' must be the same algorithm");
  }
  self->hashCipher_ = hashCipher;
  self->mainCipher_ = mainCipher;
}

LibOrgBouncycastleCryptoModesOCBBlockCipher *new_LibOrgBouncycastleCryptoModesOCBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> hashCipher, id<LibOrgBouncycastleCryptoBlockCipher> mainCipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoModesOCBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_, hashCipher, mainCipher)
}

LibOrgBouncycastleCryptoModesOCBBlockCipher *create_LibOrgBouncycastleCryptoModesOCBBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> hashCipher, id<LibOrgBouncycastleCryptoBlockCipher> mainCipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoModesOCBBlockCipher, initWithLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_, hashCipher, mainCipher)
}

IOSByteArray *LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_doubleWithByteArray_(IOSByteArray *block) {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initialize();
  IOSByteArray *result = [IOSByteArray newArrayWithLength:16];
  jint carry = LibOrgBouncycastleCryptoModesOCBBlockCipher_shiftLeftWithByteArray_withByteArray_(block, result);
  *IOSByteArray_GetRef(result, 15) ^= (JreURShift32((jint) 0x87, (JreLShift32((1 - carry), 3))));
  return result;
}

void LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_extendWithByteArray_withInt_(IOSByteArray *block, jint pos) {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initialize();
  *IOSByteArray_GetRef(nil_chk(block), pos) = (jbyte) (jint) 0x80;
  while (++pos < 16) {
    *IOSByteArray_GetRef(block, pos) = 0;
  }
}

jint LibOrgBouncycastleCryptoModesOCBBlockCipher_OCB_ntzWithLong_(jlong x) {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initialize();
  if (x == 0) {
    return 64;
  }
  jint n = 0;
  while ((x & 1LL) == 0LL) {
    ++n;
    JreURShiftAssignLong(&x, 1);
  }
  return n;
}

jint LibOrgBouncycastleCryptoModesOCBBlockCipher_shiftLeftWithByteArray_withByteArray_(IOSByteArray *block, IOSByteArray *output) {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initialize();
  jint i = 16;
  jint bit = 0;
  while (--i >= 0) {
    jint b = IOSByteArray_Get(nil_chk(block), i) & (jint) 0xff;
    *IOSByteArray_GetRef(nil_chk(output), i) = (jbyte) ((JreLShift32(b, 1)) | bit);
    bit = (JreURShift32(b, 7)) & 1;
  }
  return bit;
}

void LibOrgBouncycastleCryptoModesOCBBlockCipher_xor__WithByteArray_withByteArray_(IOSByteArray *block, IOSByteArray *val) {
  LibOrgBouncycastleCryptoModesOCBBlockCipher_initialize();
  for (jint i = 15; i >= 0; --i) {
    *IOSByteArray_GetRef(nil_chk(block), i) ^= IOSByteArray_Get(nil_chk(val), i);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoModesOCBBlockCipher)