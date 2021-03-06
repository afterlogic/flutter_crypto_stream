//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DefaultTlsSignerCredentials.java
//

#include "AbstractTlsSignerCredentials.h"
#include "AlertDescription.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "CryptoException.h"
#include "DSAPrivateKeyParameters.h"
#include "DefaultTlsSignerCredentials.h"
#include "ECPrivateKeyParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RSAKeyParameters.h"
#include "SignatureAndHashAlgorithm.h"
#include "TlsContext.h"
#include "TlsDSSSigner.h"
#include "TlsECDSASigner.h"
#include "TlsFatalAlert.h"
#include "TlsRSASigner.h"
#include "TlsSigner.h"
#include "TlsUtils.h"
#include "java/lang/IllegalArgumentException.h"

@implementation LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                   withLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate
     withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey {
  LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(self, context, certificate, privateKey);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                   withLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate
     withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
     withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)signatureAndHashAlgorithm {
  LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(self, context, certificate, privateKey, signatureAndHashAlgorithm);
  return self;
}

- (LibOrgBouncycastleCryptoTlsCertificate *)getCertificate {
  return certificate_;
}

- (IOSByteArray *)generateCertificateSignatureWithByteArray:(IOSByteArray *)hash_ {
  @try {
    if (LibOrgBouncycastleCryptoTlsTlsUtils_isTLSv12WithLibOrgBouncycastleCryptoTlsTlsContext_(context_)) {
      return [((id<LibOrgBouncycastleCryptoTlsTlsSigner>) nil_chk(signer_)) generateRawSignatureWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:signatureAndHashAlgorithm_ withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:privateKey_ withByteArray:hash_];
    }
    else {
      return [((id<LibOrgBouncycastleCryptoTlsTlsSigner>) nil_chk(signer_)) generateRawSignatureWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:privateKey_ withByteArray:hash_];
    }
  }
  @catch (LibOrgBouncycastleCryptoCryptoException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error, e);
  }
}

- (LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)getSignatureAndHashAlgorithm {
  return signatureAndHashAlgorithm_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsContext:withLibOrgBouncycastleCryptoTlsCertificate:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsContext:withLibOrgBouncycastleCryptoTlsCertificate:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:);
  methods[2].selector = @selector(getCertificate);
  methods[3].selector = @selector(generateCertificateSignatureWithByteArray:);
  methods[4].selector = @selector(getSignatureAndHashAlgorithm);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "context_", "LLibOrgBouncycastleCryptoTlsTlsContext;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "certificate_", "LLibOrgBouncycastleCryptoTlsCertificate;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "signatureAndHashAlgorithm_", "LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "signer_", "LLibOrgBouncycastleCryptoTlsTlsSigner;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoTlsTlsContext;LLibOrgBouncycastleCryptoTlsCertificate;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "LLibOrgBouncycastleCryptoTlsTlsContext;LLibOrgBouncycastleCryptoTlsCertificate;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;", "generateCertificateSignature", "[B", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials = { "DefaultTlsSignerCredentials", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials;
}

@end

void LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(self, context, certificate, privateKey, nil);
}

LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *new_LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, context, certificate, privateKey)
}

LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *create_LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, context, certificate, privateKey)
}

void LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey, LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm) {
  LibOrgBouncycastleCryptoTlsAbstractTlsSignerCredentials_init(self);
  if (certificate == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certificate' cannot be null");
  }
  if ([certificate isEmpty]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certificate' cannot be empty");
  }
  if (privateKey == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'privateKey' cannot be null");
  }
  if (![privateKey isPrivate]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'privateKey' must be private");
  }
  if (LibOrgBouncycastleCryptoTlsTlsUtils_isTLSv12WithLibOrgBouncycastleCryptoTlsTlsContext_(context) && signatureAndHashAlgorithm == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
  }
  if ([privateKey isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAKeyParameters class]]) {
    self->signer_ = new_LibOrgBouncycastleCryptoTlsTlsRSASigner_init();
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastleCryptoParamsDSAPrivateKeyParameters class]]) {
    self->signer_ = new_LibOrgBouncycastleCryptoTlsTlsDSSSigner_init();
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]]) {
    self->signer_ = new_LibOrgBouncycastleCryptoTlsTlsECDSASigner_init();
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"'privateKey' type not supported: ", [[privateKey java_getClass] getName]));
  }
  [self->signer_ init__WithLibOrgBouncycastleCryptoTlsTlsContext:context];
  self->context_ = context;
  self->certificate_ = certificate;
  self->privateKey_ = privateKey;
  self->signatureAndHashAlgorithm_ = signatureAndHashAlgorithm;
}

LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *new_LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey, LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_, context, certificate, privateKey, signatureAndHashAlgorithm)
}

LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials *create_LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey, LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_, context, certificate, privateKey, signatureAndHashAlgorithm)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDefaultTlsSignerCredentials)
