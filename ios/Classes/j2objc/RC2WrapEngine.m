//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RC2WrapEngine.java
//

#include "Arrays.h"
#include "CBCBlockCipher.h"
#include "CipherParameters.h"
#include "CryptoServicesRegistrar.h"
#include "Digest.h"
#include "DigestFactory.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "ParametersWithIV.h"
#include "ParametersWithRandom.h"
#include "RC2Engine.h"
#include "RC2WrapEngine.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoEnginesRC2WrapEngine () {
 @public
  LibOrgBouncycastleCryptoModesCBCBlockCipher *engine_;
  id<LibOrgBouncycastleCryptoCipherParameters> param_;
  LibOrgBouncycastleCryptoParamsParametersWithIV *paramPlusIV_;
  IOSByteArray *iv_;
  jboolean forWrapping_;
  JavaSecuritySecureRandom *sr_;
}

- (IOSByteArray *)calculateCMSKeyChecksumWithByteArray:(IOSByteArray *)key;

- (jboolean)checkCMSKeyChecksumWithByteArray:(IOSByteArray *)key
                               withByteArray:(IOSByteArray *)checksum;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, engine_, LibOrgBouncycastleCryptoModesCBCBlockCipher *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, param_, id<LibOrgBouncycastleCryptoCipherParameters>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, paramPlusIV_, LibOrgBouncycastleCryptoParamsParametersWithIV *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, sr_, JavaSecuritySecureRandom *)

inline IOSByteArray *LibOrgBouncycastleCryptoEnginesRC2WrapEngine_get_IV2(void);
static IOSByteArray *LibOrgBouncycastleCryptoEnginesRC2WrapEngine_IV2;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, IV2, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoEnginesRC2WrapEngine_calculateCMSKeyChecksumWithByteArray_(LibOrgBouncycastleCryptoEnginesRC2WrapEngine *self, IOSByteArray *key);

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoEnginesRC2WrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(LibOrgBouncycastleCryptoEnginesRC2WrapEngine *self, IOSByteArray *key, IOSByteArray *checksum);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoEnginesRC2WrapEngine)

@implementation LibOrgBouncycastleCryptoEnginesRC2WrapEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesRC2WrapEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  self->forWrapping_ = forWrapping;
  self->engine_ = new_LibOrgBouncycastleCryptoModesCBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(new_LibOrgBouncycastleCryptoEnginesRC2Engine_init());
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *pWithR = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    sr_ = [((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(pWithR)) getRandom];
    param = [pWithR getParameters];
  }
  else {
    sr_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
  }
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    self->paramPlusIV_ = (LibOrgBouncycastleCryptoParamsParametersWithIV *) param;
    self->iv_ = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(self->paramPlusIV_)) getIV];
    self->param_ = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(self->paramPlusIV_)) getParameters];
    if (self->forWrapping_) {
      if ((self->iv_ == nil) || (((IOSByteArray *) nil_chk(self->iv_))->size_ != 8)) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"IV is not 8 octets");
      }
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"You should not supply an IV for unwrapping");
    }
  }
  else {
    self->param_ = param;
    if (self->forWrapping_) {
      self->iv_ = [IOSByteArray newArrayWithLength:8];
      [((JavaSecuritySecureRandom *) nil_chk(sr_)) nextBytesWithByteArray:iv_];
      self->paramPlusIV_ = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(self->param_, self->iv_);
    }
  }
}

- (NSString *)getAlgorithmName {
  return @"RC2";
}

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen {
  if (!forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not initialized for wrapping");
  }
  jint length = inLen + 1;
  if ((length % 8) != 0) {
    length += 8 - (length % 8);
  }
  IOSByteArray *keyToBeWrapped = [IOSByteArray newArrayWithLength:length];
  *IOSByteArray_GetRef(keyToBeWrapped, 0) = (jbyte) inLen;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, keyToBeWrapped, 1, inLen);
  IOSByteArray *pad = [IOSByteArray newArrayWithLength:keyToBeWrapped->size_ - inLen - 1];
  if (pad->size_ > 0) {
    [((JavaSecuritySecureRandom *) nil_chk(sr_)) nextBytesWithByteArray:pad];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(pad, 0, keyToBeWrapped, inLen + 1, pad->size_);
  }
  IOSByteArray *CKS = LibOrgBouncycastleCryptoEnginesRC2WrapEngine_calculateCMSKeyChecksumWithByteArray_(self, keyToBeWrapped);
  IOSByteArray *WKCKS = [IOSByteArray newArrayWithLength:keyToBeWrapped->size_ + ((IOSByteArray *) nil_chk(CKS))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(keyToBeWrapped, 0, WKCKS, 0, keyToBeWrapped->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(CKS, 0, WKCKS, keyToBeWrapped->size_, CKS->size_);
  IOSByteArray *TEMP1 = [IOSByteArray newArrayWithLength:WKCKS->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(WKCKS, 0, TEMP1, 0, WKCKS->size_);
  jint noOfBlocks = WKCKS->size_ / [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
  jint extraBytes = WKCKS->size_ % [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
  if (extraBytes != 0) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not multiple of block length");
  }
  [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:paramPlusIV_];
  for (jint i = 0; i < noOfBlocks; i++) {
    jint currentBytePos = i * [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
    [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:TEMP1 withInt:currentBytePos withByteArray:TEMP1 withInt:currentBytePos];
  }
  IOSByteArray *TEMP2 = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(self->iv_))->size_ + TEMP1->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->iv_, 0, TEMP2, 0, self->iv_->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP1, 0, TEMP2, ((IOSByteArray *) nil_chk(self->iv_))->size_, TEMP1->size_);
  IOSByteArray *TEMP3 = [IOSByteArray newArrayWithLength:TEMP2->size_];
  for (jint i = 0; i < TEMP2->size_; i++) {
    *IOSByteArray_GetRef(TEMP3, i) = IOSByteArray_Get(TEMP2, TEMP2->size_ - (i + 1));
  }
  LibOrgBouncycastleCryptoParamsParametersWithIV *param2 = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(self->param_, LibOrgBouncycastleCryptoEnginesRC2WrapEngine_IV2);
  [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param2];
  for (jint i = 0; i < noOfBlocks + 1; i++) {
    jint currentBytePos = i * [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
    [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:TEMP3 withInt:currentBytePos withByteArray:TEMP3 withInt:currentBytePos];
  }
  return TEMP3;
}

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen {
  if (forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not set for unwrapping");
  }
  if (inArg == nil) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"Null pointer as ciphertext");
  }
  if (inLen % [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize] != 0) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(JreStrcat("$I", @"Ciphertext not multiple of ", [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize]));
  }
  LibOrgBouncycastleCryptoParamsParametersWithIV *param2 = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(self->param_, LibOrgBouncycastleCryptoEnginesRC2WrapEngine_IV2);
  [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param2];
  IOSByteArray *TEMP3 = [IOSByteArray newArrayWithLength:inLen];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, TEMP3, 0, inLen);
  for (jint i = 0; i < (TEMP3->size_ / [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize]); i++) {
    jint currentBytePos = i * [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
    [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:TEMP3 withInt:currentBytePos withByteArray:TEMP3 withInt:currentBytePos];
  }
  IOSByteArray *TEMP2 = [IOSByteArray newArrayWithLength:TEMP3->size_];
  for (jint i = 0; i < TEMP3->size_; i++) {
    *IOSByteArray_GetRef(TEMP2, i) = IOSByteArray_Get(TEMP3, TEMP3->size_ - (i + 1));
  }
  self->iv_ = [IOSByteArray newArrayWithLength:8];
  IOSByteArray *TEMP1 = [IOSByteArray newArrayWithLength:TEMP2->size_ - 8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP2, 0, self->iv_, 0, 8);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP2, 8, TEMP1, 0, TEMP2->size_ - 8);
  self->paramPlusIV_ = new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_(self->param_, self->iv_);
  [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:self->paramPlusIV_];
  IOSByteArray *LCEKPADICV = [IOSByteArray newArrayWithLength:TEMP1->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP1, 0, LCEKPADICV, 0, TEMP1->size_);
  for (jint i = 0; i < (LCEKPADICV->size_ / [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize]); i++) {
    jint currentBytePos = i * [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
    [((LibOrgBouncycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:LCEKPADICV withInt:currentBytePos withByteArray:LCEKPADICV withInt:currentBytePos];
  }
  IOSByteArray *result = [IOSByteArray newArrayWithLength:LCEKPADICV->size_ - 8];
  IOSByteArray *CKStoBeVerified = [IOSByteArray newArrayWithLength:8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(LCEKPADICV, 0, result, 0, LCEKPADICV->size_ - 8);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(LCEKPADICV, LCEKPADICV->size_ - 8, CKStoBeVerified, 0, 8);
  if (!LibOrgBouncycastleCryptoEnginesRC2WrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(self, result, CKStoBeVerified)) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(@"Checksum inside ciphertext is corrupted");
  }
  if ((result->size_ - ((IOSByteArray_Get(result, 0) & (jint) 0xff) + 1)) > 7) {
    @throw new_LibOrgBouncycastleCryptoInvalidCipherTextException_initWithNSString_(JreStrcat("$IC", @"too many pad bytes (", (result->size_ - ((IOSByteArray_Get(result, 0) & (jint) 0xff) + 1)), ')'));
  }
  IOSByteArray *CEK = [IOSByteArray newArrayWithLength:IOSByteArray_Get(result, 0)];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(result, 1, CEK, 0, CEK->size_);
  return CEK;
}

- (IOSByteArray *)calculateCMSKeyChecksumWithByteArray:(IOSByteArray *)key {
  return LibOrgBouncycastleCryptoEnginesRC2WrapEngine_calculateCMSKeyChecksumWithByteArray_(self, key);
}

- (jboolean)checkCMSKeyChecksumWithByteArray:(IOSByteArray *)key
                               withByteArray:(IOSByteArray *)checksum {
  return LibOrgBouncycastleCryptoEnginesRC2WrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(self, key, checksum);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 3, 5, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(wrapWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(unwrapWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(calculateCMSKeyChecksumWithByteArray:);
  methods[6].selector = @selector(checkCMSKeyChecksumWithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "engine_", "LLibOrgBouncycastleCryptoModesCBCBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "paramPlusIV_", "LLibOrgBouncycastleCryptoParamsParametersWithIV;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forWrapping_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sr_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "IV2", "[B", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "sha1_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "digest_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "wrap", "[BII", "unwrap", "LLibOrgBouncycastleCryptoInvalidCipherTextException;", "calculateCMSKeyChecksum", "[B", "checkCMSKeyChecksum", "[B[B", &LibOrgBouncycastleCryptoEnginesRC2WrapEngine_IV2 };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesRC2WrapEngine = { "RC2WrapEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 7, 9, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesRC2WrapEngine;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoEnginesRC2WrapEngine class]) {
    LibOrgBouncycastleCryptoEnginesRC2WrapEngine_IV2 = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0x4a, (jbyte) (jint) 0xdd, (jbyte) (jint) 0xa2, (jbyte) (jint) 0x2c, (jbyte) (jint) 0x79, (jbyte) (jint) 0xe8, (jbyte) (jint) 0x21, (jbyte) (jint) 0x05 } count:8];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoEnginesRC2WrapEngine)
  }
}

@end

void LibOrgBouncycastleCryptoEnginesRC2WrapEngine_init(LibOrgBouncycastleCryptoEnginesRC2WrapEngine *self) {
  NSObject_init(self);
  self->sha1_ = LibOrgBouncycastleCryptoUtilDigestFactory_createSHA1();
  self->digest_ = [IOSByteArray newArrayWithLength:20];
}

LibOrgBouncycastleCryptoEnginesRC2WrapEngine *new_LibOrgBouncycastleCryptoEnginesRC2WrapEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, init)
}

LibOrgBouncycastleCryptoEnginesRC2WrapEngine *create_LibOrgBouncycastleCryptoEnginesRC2WrapEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesRC2WrapEngine, init)
}

IOSByteArray *LibOrgBouncycastleCryptoEnginesRC2WrapEngine_calculateCMSKeyChecksumWithByteArray_(LibOrgBouncycastleCryptoEnginesRC2WrapEngine *self, IOSByteArray *key) {
  IOSByteArray *result = [IOSByteArray newArrayWithLength:8];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->sha1_)) updateWithByteArray:key withInt:0 withInt:((IOSByteArray *) nil_chk(key))->size_];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->sha1_)) doFinalWithByteArray:self->digest_ withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->digest_, 0, result, 0, 8);
  return result;
}

jboolean LibOrgBouncycastleCryptoEnginesRC2WrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(LibOrgBouncycastleCryptoEnginesRC2WrapEngine *self, IOSByteArray *key, IOSByteArray *checksum) {
  return LibOrgBouncycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(LibOrgBouncycastleCryptoEnginesRC2WrapEngine_calculateCMSKeyChecksumWithByteArray_(self, key), checksum);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesRC2WrapEngine)
