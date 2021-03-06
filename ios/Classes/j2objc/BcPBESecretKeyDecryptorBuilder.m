//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPBESecretKeyDecryptorBuilder.java
//

#include "BcImplProvider.h"
#include "BcPBESecretKeyDecryptorBuilder.h"
#include "BcUtil.h"
#include "BlockCipher.h"
#include "BufferedBlockCipher.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "PBESecretKeyDecryptor.h"
#include "PGPDigestCalculatorProvider.h"
#include "PGPException.h"

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder () {
 @public
  id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder, calculatorProvider_, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)

@interface LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 : LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor

- (instancetype)initWithCharArray:(IOSCharArray *)passPhrase
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)calculatorProvider;

- (IOSByteArray *)recoverKeyDataWithInt:(jint)encAlgorithm
                          withByteArray:(IOSByteArray *)key
                          withByteArray:(IOSByteArray *)iv
                          withByteArray:(IOSByteArray *)keyData
                                withInt:(jint)keyOff
                                withInt:(jint)keyLen;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *self, IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider);

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)calculatorProvider {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(self, calculatorProvider);
  return self;
}

- (LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor *)buildWithCharArray:(IOSCharArray *)passPhrase {
  return new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(passPhrase, calculatorProvider_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor;", 0x1, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:);
  methods[1].selector = @selector(buildWithCharArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "calculatorProvider_", "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider;", "build", "[C" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder = { "BcPBESecretKeyDecryptorBuilder", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder *self, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  NSObject_init(self);
  self->calculatorProvider_ = calculatorProvider;
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder, initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_, calculatorProvider)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder, initWithLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_, calculatorProvider)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder)

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1

- (instancetype)initWithCharArray:(IOSCharArray *)passPhrase
withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:(id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)calculatorProvider {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(self, passPhrase, calculatorProvider);
  return self;
}

- (IOSByteArray *)recoverKeyDataWithInt:(jint)encAlgorithm
                          withByteArray:(IOSByteArray *)key
                          withByteArray:(IOSByteArray *)iv
                          withByteArray:(IOSByteArray *)keyData
                                withInt:(jint)keyOff
                                withInt:(jint)keyLen {
  @try {
    LibOrgBouncycastleCryptoBufferedBlockCipher *c = LibOrgBouncycastleOpenpgpOperatorBcBcUtil_createSymmetricKeyWrapperWithBoolean_withLibOrgBouncycastleCryptoBlockCipher_withByteArray_withByteArray_(false, LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createBlockCipherWithInt_(encAlgorithm), key, iv);
    IOSByteArray *out = [IOSByteArray newArrayWithLength:keyLen];
    jint outLen = [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(c)) processBytesWithByteArray:keyData withInt:keyOff withInt:keyLen withByteArray:out withInt:0];
    outLen += [c doFinalWithByteArray:out withInt:outLen];
    return out;
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$$", @"decryption failed: ", [e getMessage]), e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider:);
  methods[1].selector = @selector(recoverKeyDataWithInt:withByteArray:withByteArray:withByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[CLLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider;", "recoverKeyData", "I[B[B[BII", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder;", "buildWithCharArray:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 = { "", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, NULL, 7, 0x8010, 2, 0, 4, -1, 5, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *self, IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  LibOrgBouncycastleOpenpgpOperatorPBESecretKeyDecryptor_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(self, passPhrase, calculatorProvider);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1, initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_, passPhrase, calculatorProvider)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(IOSCharArray *passPhrase, id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider> calculatorProvider) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBESecretKeyDecryptorBuilder_1, initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_, passPhrase, calculatorProvider)
}
