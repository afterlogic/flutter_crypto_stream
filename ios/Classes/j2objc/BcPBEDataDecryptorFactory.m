//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/BcPBEDataDecryptorFactory.java
//

#include "BcImplProvider.h"
#include "BcPBEDataDecryptorFactory.h"
#include "BcPGPDigestCalculatorProvider.h"
#include "BcUtil.h"
#include "BlockCipher.h"
#include "BufferedBlockCipher.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PBEDataDecryptorFactory.h"
#include "PGPDataDecryptor.h"
#include "PGPException.h"
#include "java/lang/Exception.h"
#include "java/lang/System.h"

@implementation LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory

- (instancetype)initWithCharArray:(IOSCharArray *)pass
withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider:(LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *)calculatorProvider {
  LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_(self, pass, calculatorProvider);
  return self;
}

- (IOSByteArray *)recoverSessionDataWithInt:(jint)keyAlgorithm
                              withByteArray:(IOSByteArray *)key
                              withByteArray:(IOSByteArray *)secKeyData {
  @try {
    if (secKeyData != nil && secKeyData->size_ > 0) {
      id<LibOrgBouncycastleCryptoBlockCipher> engine = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createBlockCipherWithInt_(keyAlgorithm);
      LibOrgBouncycastleCryptoBufferedBlockCipher *cipher = LibOrgBouncycastleOpenpgpOperatorBcBcUtil_createSymmetricKeyWrapperWithBoolean_withLibOrgBouncycastleCryptoBlockCipher_withByteArray_withByteArray_(false, engine, key, [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize]]);
      IOSByteArray *out = [IOSByteArray newArrayWithLength:secKeyData->size_];
      jint len = [((LibOrgBouncycastleCryptoBufferedBlockCipher *) nil_chk(cipher)) processBytesWithByteArray:secKeyData withInt:0 withInt:secKeyData->size_ withByteArray:out withInt:0];
      len += [cipher doFinalWithByteArray:out withInt:len];
      return out;
    }
    else {
      IOSByteArray *keyBytes = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(key))->size_ + 1];
      *IOSByteArray_GetRef(keyBytes, 0) = (jbyte) keyAlgorithm;
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(key, 0, keyBytes, 1, key->size_);
      return keyBytes;
    }
  }
  @catch (JavaLangException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(@"Exception recovering session info", e);
  }
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor>)createDataDecryptorWithBoolean:(jboolean)withIntegrityPacket
                                                                                withInt:(jint)encAlgorithm
                                                                          withByteArray:(IOSByteArray *)key {
  id<LibOrgBouncycastleCryptoBlockCipher> engine = LibOrgBouncycastleOpenpgpOperatorBcBcImplProvider_createBlockCipherWithInt_(encAlgorithm);
  return LibOrgBouncycastleOpenpgpOperatorBcBcUtil_createDataDecryptorWithBoolean_withLibOrgBouncycastleCryptoBlockCipher_withByteArray_(withIntegrityPacket, engine, key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor;", 0x1, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider:);
  methods[1].selector = @selector(recoverSessionDataWithInt:withByteArray:withByteArray:);
  methods[2].selector = @selector(createDataDecryptorWithBoolean:withInt:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "[CLLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider;", "recoverSessionData", "I[B[B", "LLibOrgBouncycastleOpenpgpPGPException;", "createDataDecryptor", "ZI[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory = { "BcPBEDataDecryptorFactory", "lib.org.bouncycastle.openpgp.operator.bc", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory;
}

@end

void LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_(LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory *self, IOSCharArray *pass, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *calculatorProvider) {
  LibOrgBouncycastleOpenpgpOperatorPBEDataDecryptorFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider_(self, pass, calculatorProvider);
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory *new_LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_(IOSCharArray *pass, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *calculatorProvider) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory, initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_, pass, calculatorProvider)
}

LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory *create_LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory_initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_(IOSCharArray *pass, LibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider *calculatorProvider) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory, initWithCharArray_withLibOrgBouncycastleOpenpgpOperatorBcBcPGPDigestCalculatorProvider_, pass, calculatorProvider)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorBcBcPBEDataDecryptorFactory)
