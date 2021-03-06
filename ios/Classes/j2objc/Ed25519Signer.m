//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/Ed25519Signer.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "Ed25519.h"
#include "Ed25519PrivateKeyParameters.h"
#include "Ed25519PublicKeyParameters.h"
#include "Ed25519Signer.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/IllegalStateException.h"

@class LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer;

@interface LibOrgBouncycastleCryptoSignersEd25519Signer () {
 @public
  LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *buffer_;
  jboolean forSigning_;
  LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *privateKey_;
  LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *publicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519Signer, buffer_, LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519Signer, privateKey_, LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519Signer, publicKey_, LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)

@interface LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer : JavaIoByteArrayOutputStream

- (instancetype)init;

- (IOSByteArray *)generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)privateKey
                                    withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey;

- (jboolean)verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                          withByteArray:(IOSByteArray *)signature;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer)

__attribute__((unused)) static void LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *new_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *create_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer)

@implementation LibOrgBouncycastleCryptoSignersEd25519Signer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersEd25519Signer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  self->forSigning_ = forSigning;
  if (forSigning) {
    self->privateKey_ = (LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters class]);
    self->publicKey_ = [((LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) nil_chk(privateKey_)) generatePublicKey];
  }
  else {
    self->privateKey_ = nil;
    self->publicKey_ = (LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters class]);
  }
  [self reset];
}

- (void)updateWithByte:(jbyte)b {
  [((LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *) nil_chk(buffer_)) writeWithInt:b];
}

- (void)updateWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off
                    withInt:(jint)len {
  [((LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *) nil_chk(buffer_)) writeWithByteArray:buf withInt:off withInt:len];
}

- (IOSByteArray *)generateSignature {
  if (!forSigning_ || nil == privateKey_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Ed25519Signer not initialised for signature generation.");
  }
  return [((LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *) nil_chk(buffer_)) generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:privateKey_ withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey_];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature {
  if (forSigning_ || nil == publicKey_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Ed25519Signer not initialised for verification");
  }
  return [((LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *) nil_chk(buffer_)) verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey_ withByteArray:signature];
}

- (void)reset {
  [((LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *) nil_chk(buffer_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(updateWithByte:);
  methods[3].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(generateSignature);
  methods[5].selector = @selector(verifySignatureWithByteArray:);
  methods[6].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buffer_", "LLibOrgBouncycastleCryptoSignersEd25519Signer_Buffer;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "forSigning_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "verifySignature", "[B", "LLibOrgBouncycastleCryptoSignersEd25519Signer_Buffer;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersEd25519Signer = { "Ed25519Signer", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 7, 4, -1, 7, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersEd25519Signer;
}

@end

void LibOrgBouncycastleCryptoSignersEd25519Signer_init(LibOrgBouncycastleCryptoSignersEd25519Signer *self) {
  NSObject_init(self);
  self->buffer_ = new_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init();
}

LibOrgBouncycastleCryptoSignersEd25519Signer *new_LibOrgBouncycastleCryptoSignersEd25519Signer_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersEd25519Signer, init)
}

LibOrgBouncycastleCryptoSignersEd25519Signer *create_LibOrgBouncycastleCryptoSignersEd25519Signer_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersEd25519Signer, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersEd25519Signer)

@implementation LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)privateKey
                                    withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey {
  @synchronized(self) {
    IOSByteArray *signature = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_SIGNATURE_SIZE];
    [((LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) nil_chk(privateKey)) signWithInt:LibOrgBouncycastleMathEcRfc8032Ed25519_Algorithm_Ed25519 withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey withByteArray:nil withByteArray:buf_ withInt:0 withInt:count_ withByteArray:signature withInt:0];
    [self reset];
    return signature;
  }
}

- (jboolean)verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                          withByteArray:(IOSByteArray *)signature {
  @synchronized(self) {
    IOSByteArray *pk = [((LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) nil_chk(publicKey)) getEncoded];
    jboolean result = LibOrgBouncycastleMathEcRfc8032Ed25519_verifyWithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_withInt_(signature, 0, pk, 0, buf_, 0, count_);
    [self reset];
    return result;
  }
}

- (void)reset {
  @synchronized(self) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withInt_withInt_withByte_(buf_, 0, count_, (jbyte) 0);
    self->count_ = 0;
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x20, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x20, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x21, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:);
  methods[2].selector = @selector(verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:withByteArray:);
  methods[3].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generateSignature", "LLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters;LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;", "verifySignature", "LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;[B", "LLibOrgBouncycastleCryptoSignersEd25519Signer;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer = { "Buffer", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, NULL, 7, 0xa, 4, 0, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer;
}

@end

void LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *self) {
  JavaIoByteArrayOutputStream_init(self);
}

LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *new_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer, init)
}

LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer *create_LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersEd25519Signer_Buffer)
