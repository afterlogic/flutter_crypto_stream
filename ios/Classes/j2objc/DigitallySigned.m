//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DigitallySigned.java
//

#include "DigitallySigned.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SignatureAndHashAlgorithm.h"
#include "TlsContext.h"
#include "TlsUtils.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"

@implementation LibOrgBouncycastleCryptoTlsDigitallySigned

- (instancetype)initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                               withByteArray:(IOSByteArray *)signature {
  LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(self, algorithm, signature);
  return self;
}

- (LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)getAlgorithm {
  return algorithm_;
}

- (IOSByteArray *)getSignature {
  return signature_;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  if (algorithm_ != nil) {
    [algorithm_ encodeWithJavaIoOutputStream:output];
  }
  LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(signature_, output);
}

+ (LibOrgBouncycastleCryptoTlsDigitallySigned *)parseWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                         withJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsDigitallySigned_parseWithLibOrgBouncycastleCryptoTlsTlsContext_withJavaIoInputStream_(context, input);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsDigitallySigned;", 0x9, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:withByteArray:);
  methods[1].selector = @selector(getAlgorithm);
  methods[2].selector = @selector(getSignature);
  methods[3].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[4].selector = @selector(parseWithLibOrgBouncycastleCryptoTlsTlsContext:withJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithm_", "LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "signature_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;[B", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LLibOrgBouncycastleCryptoTlsTlsContext;LJavaIoInputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDigitallySigned = { "DigitallySigned", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDigitallySigned;
}

@end

void LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(LibOrgBouncycastleCryptoTlsDigitallySigned *self, LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature) {
  NSObject_init(self);
  if (signature == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'signature' cannot be null");
  }
  self->algorithm_ = algorithm;
  self->signature_ = signature;
}

LibOrgBouncycastleCryptoTlsDigitallySigned *new_LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDigitallySigned, initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_, algorithm, signature)
}

LibOrgBouncycastleCryptoTlsDigitallySigned *create_LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDigitallySigned, initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_, algorithm, signature)
}

LibOrgBouncycastleCryptoTlsDigitallySigned *LibOrgBouncycastleCryptoTlsDigitallySigned_parseWithLibOrgBouncycastleCryptoTlsTlsContext_withJavaIoInputStream_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsDigitallySigned_initialize();
  LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *algorithm = nil;
  if (LibOrgBouncycastleCryptoTlsTlsUtils_isTLSv12WithLibOrgBouncycastleCryptoTlsTlsContext_(context)) {
    algorithm = LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_parseWithJavaIoInputStream_(input);
  }
  IOSByteArray *signature = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
  return new_LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(algorithm, signature);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDigitallySigned)
