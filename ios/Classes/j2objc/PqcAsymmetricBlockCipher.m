//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/util/PqcAsymmetricBlockCipher.java
//

#include "CipherSpiExt.h"
#include "CryptoServicesRegistrar.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PqcAsymmetricBlockCipher.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/System.h"
#include "java/security/InvalidAlgorithmParameterException.h"
#include "java/security/InvalidParameterException.h"
#include "java/security/Key.h"
#include "java/security/SecureRandom.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "javax/crypto/IllegalBlockSizeException.h"
#include "javax/crypto/ShortBufferException.h"

__attribute__((unused)) static jint LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getBlockSize(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self);

__attribute__((unused)) static jint LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getOutputSizeWithInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, jint inLen);

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> params, JavaSecuritySecureRandom *secureRandom);

__attribute__((unused)) static void LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initDecryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> params);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_updateWithByteArray_withInt_withInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, IOSByteArray *input, jint inOff, jint inLen);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_doFinalWithByteArray_withInt_withInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, IOSByteArray *input, jint inOff, jint inLen);

@implementation LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jint)getBlockSize {
  return LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getBlockSize(self);
}

- (IOSByteArray *)getIV {
  return nil;
}

- (jint)getOutputSizeWithInt:(jint)inLen {
  return LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getOutputSizeWithInt_(self, inLen);
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)getParameters {
  return paramSpec_;
}

- (void)initEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  @try {
    LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(self, key, nil, LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom());
  }
  @catch (JavaSecurityInvalidAlgorithmParameterException *e) {
    @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"This cipher needs algorithm parameters for initialization (cannot be null).");
  }
}

- (void)initEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  @try {
    LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(self, key, nil, random);
  }
  @catch (JavaSecurityInvalidAlgorithmParameterException *iape) {
    @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"This cipher needs algorithm parameters for initialization (cannot be null).");
  }
}

- (void)initEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(self, key, params, LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom());
}

- (void)initEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
          withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom {
  LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(self, key, params, secureRandom);
}

- (void)initDecryptWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  @try {
    LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initDecryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(self, key, nil);
  }
  @catch (JavaSecurityInvalidAlgorithmParameterException *iape) {
    @throw new_JavaSecurityInvalidParameterException_initWithNSString_(@"This cipher needs algorithm parameters for initialization (cannot be null).");
  }
}

- (void)initDecryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initDecryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(self, key, params);
}

- (IOSByteArray *)updateWithByteArray:(IOSByteArray *)input
                              withInt:(jint)inOff
                              withInt:(jint)inLen {
  return LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_updateWithByteArray_withInt_withInt_(self, input, inOff, inLen);
}

- (jint)updateWithByteArray:(IOSByteArray *)input
                    withInt:(jint)inOff
                    withInt:(jint)inLen
              withByteArray:(IOSByteArray *)output
                    withInt:(jint)outOff {
  (void) LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_updateWithByteArray_withInt_withInt_(self, input, inOff, inLen);
  return 0;
}

- (IOSByteArray *)doFinalWithByteArray:(IOSByteArray *)input
                               withInt:(jint)inOff
                               withInt:(jint)inLen {
  return LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_doFinalWithByteArray_withInt_withInt_(self, input, inOff, inLen);
}

- (jint)doFinalWithByteArray:(IOSByteArray *)input
                     withInt:(jint)inOff
                     withInt:(jint)inLen
               withByteArray:(IOSByteArray *)output
                     withInt:(jint)outOff {
  if (((IOSByteArray *) nil_chk(output))->size_ < LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getOutputSizeWithInt_(self, inLen)) {
    @throw new_JavaxCryptoShortBufferException_initWithNSString_(@"Output buffer too short.");
  }
  IOSByteArray *out = LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_doFinalWithByteArray_withInt_withInt_(self, input, inOff, inLen);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(out, 0, output, outOff, ((IOSByteArray *) nil_chk(out))->size_);
  return out->size_;
}

- (void)setModeWithNSString:(NSString *)modeName {
}

- (void)setPaddingWithNSString:(NSString *)paddingName {
}

- (void)checkLengthWithInt:(jint)inLen {
  jint inLength = inLen + [((JavaIoByteArrayOutputStream *) nil_chk(buf_)) size];
  if (opMode_ == LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_ENCRYPT_MODE) {
    if (inLength > maxPlainTextSize_) {
      @throw new_JavaxCryptoIllegalBlockSizeException_initWithNSString_(JreStrcat("$I$I$", @"The length of the plaintext (", inLength, @" bytes) is not supported by the cipher (max. ", maxPlainTextSize_, @" bytes)."));
    }
  }
  else if (opMode_ == LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_DECRYPT_MODE) {
    if (inLength != cipherTextSize_) {
      @throw new_JavaxCryptoIllegalBlockSizeException_initWithNSString_(JreStrcat("$I$I$", @"Illegal ciphertext length (expected ", cipherTextSize_, @" bytes, was ", inLength, @" bytes)."));
    }
  }
}

- (void)initCipherEncryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
  withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)initCipherDecryptWithJavaSecurityKey:(id<JavaSecurityKey>)key
  withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (IOSByteArray *)messageEncryptWithByteArray:(IOSByteArray *)input {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (IOSByteArray *)messageDecryptWithByteArray:(IOSByteArray *)input {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x11, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x11, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x11, 2, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x11, 2, 5, 4, -1, -1, -1 },
    { NULL, "V", 0x11, 2, 6, 7, -1, -1, -1 },
    { NULL, "V", 0x11, 2, 8, 7, -1, -1, -1 },
    { NULL, "V", 0x11, 9, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x11, 9, 6, 7, -1, -1, -1 },
    { NULL, "[B", 0x11, 10, 11, -1, -1, -1, -1 },
    { NULL, "I", 0x11, 10, 12, -1, -1, -1, -1 },
    { NULL, "[B", 0x11, 13, 11, 14, -1, -1, -1 },
    { NULL, "I", 0x11, 13, 12, 15, -1, -1, -1 },
    { NULL, "V", 0x14, 16, 17, -1, -1, -1, -1 },
    { NULL, "V", 0x14, 18, 17, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 19, 1, 20, -1, -1, -1 },
    { NULL, "V", 0x404, 21, 8, 7, -1, -1, -1 },
    { NULL, "V", 0x404, 22, 6, 7, -1, -1, -1 },
    { NULL, "[B", 0x404, 23, 24, 14, -1, -1, -1 },
    { NULL, "[B", 0x404, 25, 24, 14, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getBlockSize);
  methods[2].selector = @selector(getIV);
  methods[3].selector = @selector(getOutputSizeWithInt:);
  methods[4].selector = @selector(getParameters);
  methods[5].selector = @selector(initEncryptWithJavaSecurityKey:);
  methods[6].selector = @selector(initEncryptWithJavaSecurityKey:withJavaSecuritySecureRandom:);
  methods[7].selector = @selector(initEncryptWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:);
  methods[8].selector = @selector(initEncryptWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[9].selector = @selector(initDecryptWithJavaSecurityKey:);
  methods[10].selector = @selector(initDecryptWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:);
  methods[11].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[12].selector = @selector(updateWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[13].selector = @selector(doFinalWithByteArray:withInt:withInt:);
  methods[14].selector = @selector(doFinalWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[15].selector = @selector(setModeWithNSString:);
  methods[16].selector = @selector(setPaddingWithNSString:);
  methods[17].selector = @selector(checkLengthWithInt:);
  methods[18].selector = @selector(initCipherEncryptWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:withJavaSecuritySecureRandom:);
  methods[19].selector = @selector(initCipherDecryptWithJavaSecurityKey:withJavaSecuritySpecAlgorithmParameterSpec:);
  methods[20].selector = @selector(messageEncryptWithByteArray:);
  methods[21].selector = @selector(messageDecryptWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "paramSpec_", "LJavaSecuritySpecAlgorithmParameterSpec;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "buf_", "LJavaIoByteArrayOutputStream;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "maxPlainTextSize_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "cipherTextSize_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getOutputSize", "I", "initEncrypt", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;", "LJavaSecurityKey;LJavaSecuritySecureRandom;", "LJavaSecurityKey;LJavaSecuritySpecAlgorithmParameterSpec;", "LJavaSecurityInvalidKeyException;LJavaSecurityInvalidAlgorithmParameterException;", "LJavaSecurityKey;LJavaSecuritySpecAlgorithmParameterSpec;LJavaSecuritySecureRandom;", "initDecrypt", "update", "[BII", "[BII[BI", "doFinal", "LJavaxCryptoIllegalBlockSizeException;LJavaxCryptoBadPaddingException;", "LJavaxCryptoShortBufferException;LJavaxCryptoIllegalBlockSizeException;LJavaxCryptoBadPaddingException;", "setMode", "LNSString;", "setPadding", "checkLength", "LJavaxCryptoIllegalBlockSizeException;", "initCipherEncrypt", "initCipherDecrypt", "messageEncrypt", "[B", "messageDecrypt" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher = { "PqcAsymmetricBlockCipher", "lib.org.bouncycastle.pqc.jcajce.provider.util", ptrTable, methods, fields, 7, 0x401, 22, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher;
}

@end

void LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_init(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self) {
  LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_init(self);
  self->buf_ = new_JavaIoByteArrayOutputStream_init();
}

jint LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getBlockSize(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self) {
  return self->opMode_ == LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_ENCRYPT_MODE ? self->maxPlainTextSize_ : self->cipherTextSize_;
}

jint LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getOutputSizeWithInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, jint inLen) {
  jint totalLen = inLen + [((JavaIoByteArrayOutputStream *) nil_chk(self->buf_)) size];
  jint maxLen = LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_getBlockSize(self);
  if (totalLen > maxLen) {
    return 0;
  }
  return self->opMode_ == LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_ENCRYPT_MODE ? self->cipherTextSize_ : self->maxPlainTextSize_;
}

void LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initEncryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> params, JavaSecuritySecureRandom *secureRandom) {
  self->opMode_ = LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_ENCRYPT_MODE;
  [self initCipherEncryptWithJavaSecurityKey:key withJavaSecuritySpecAlgorithmParameterSpec:params withJavaSecuritySecureRandom:secureRandom];
}

void LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_initDecryptWithJavaSecurityKey_withJavaSecuritySpecAlgorithmParameterSpec_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, id<JavaSecurityKey> key, id<JavaSecuritySpecAlgorithmParameterSpec> params) {
  self->opMode_ = LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_DECRYPT_MODE;
  [self initCipherDecryptWithJavaSecurityKey:key withJavaSecuritySpecAlgorithmParameterSpec:params];
}

IOSByteArray *LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_updateWithByteArray_withInt_withInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, IOSByteArray *input, jint inOff, jint inLen) {
  if (inLen != 0) {
    [((JavaIoByteArrayOutputStream *) nil_chk(self->buf_)) writeWithByteArray:input withInt:inOff withInt:inLen];
  }
  return [IOSByteArray newArrayWithLength:0];
}

IOSByteArray *LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_doFinalWithByteArray_withInt_withInt_(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher *self, IOSByteArray *input, jint inOff, jint inLen) {
  [self checkLengthWithInt:inLen];
  (void) LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher_updateWithByteArray_withInt_withInt_(self, input, inOff, inLen);
  IOSByteArray *mBytes = [((JavaIoByteArrayOutputStream *) nil_chk(self->buf_)) toByteArray];
  [((JavaIoByteArrayOutputStream *) nil_chk(self->buf_)) reset];
  switch (self->opMode_) {
    case LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_ENCRYPT_MODE:
    return [self messageEncryptWithByteArray:mBytes];
    case LibOrgBouncycastlePqcJcajceProviderUtilCipherSpiExt_DECRYPT_MODE:
    return [self messageDecryptWithByteArray:mBytes];
    default:
    return nil;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderUtilPqcAsymmetricBlockCipher)
