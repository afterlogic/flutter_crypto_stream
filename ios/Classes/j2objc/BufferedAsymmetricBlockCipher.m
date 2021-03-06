//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/BufferedAsymmetricBlockCipher.java
//

#include "AsymmetricBlockCipher.h"
#include "BufferedAsymmetricBlockCipher.h"
#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher () {
 @public
  id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher, cipher_, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)

@implementation LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher

- (instancetype)initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)cipher {
  LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(self, cipher);
  return self;
}

- (id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>)getUnderlyingCipher {
  return cipher_;
}

- (jint)getBufferPosition {
  return bufOff_;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  [self reset];
  [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) init__WithBoolean:forEncryption withLibOrgBouncycastleCryptoCipherParameters:params];
  buf_ = [IOSByteArray newArrayWithLength:[cipher_ getInputBlockSize] + (forEncryption ? 1 : 0)];
  bufOff_ = 0;
}

- (jint)getInputBlockSize {
  return [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) getInputBlockSize];
}

- (jint)getOutputBlockSize {
  return [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) getOutputBlockSize];
}

- (void)processByteWithByte:(jbyte)inArg {
  if (bufOff_ >= ((IOSByteArray *) nil_chk(buf_))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"attempt to process message too long for cipher");
  }
  *IOSByteArray_GetRef(buf_, bufOff_++) = inArg;
}

- (void)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len {
  if (len == 0) {
    return;
  }
  if (len < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Can't have a negative input length!");
  }
  if (bufOff_ + len > ((IOSByteArray *) nil_chk(buf_))->size_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"attempt to process message too long for cipher");
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, buf_, bufOff_, len);
  bufOff_ += len;
}

- (IOSByteArray *)doFinal {
  IOSByteArray *out = [((id<LibOrgBouncycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:buf_ withInt:0 withInt:bufOff_];
  [self reset];
  return out;
}

- (void)reset {
  if (buf_ != nil) {
    for (jint i = 0; i < buf_->size_; i++) {
      *IOSByteArray_GetRef(buf_, i) = 0;
    }
  }
  bufOff_ = 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher:);
  methods[1].selector = @selector(getUnderlyingCipher);
  methods[2].selector = @selector(getBufferPosition);
  methods[3].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(getInputBlockSize);
  methods[5].selector = @selector(getOutputBlockSize);
  methods[6].selector = @selector(processByteWithByte:);
  methods[7].selector = @selector(processBytesWithByteArray:withInt:withInt:);
  methods[8].selector = @selector(doFinal);
  methods[9].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buf_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "bufOff_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "cipher_", "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoAsymmetricBlockCipher;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "processByte", "B", "processBytes", "[BII", "LLibOrgBouncycastleCryptoInvalidCipherTextException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher = { "BufferedAsymmetricBlockCipher", "lib.org.bouncycastle.crypto", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher;
}

@end

void LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher *self, id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  NSObject_init(self);
  self->cipher_ = cipher;
}

LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher *new_LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_, cipher)
}

LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher *create_LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher_initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_(id<LibOrgBouncycastleCryptoAsymmetricBlockCipher> cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher, initWithLibOrgBouncycastleCryptoAsymmetricBlockCipher_, cipher)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoBufferedAsymmetricBlockCipher)
