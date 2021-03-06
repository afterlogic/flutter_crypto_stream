//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DefaultTlsEncryptionCredentials.java
//

#include "AbstractTlsEncryptionCredentials.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "DefaultTlsEncryptionCredentials.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RSAKeyParameters.h"
#include "TlsContext.h"
#include "TlsRSAUtils.h"
#include "java/lang/IllegalArgumentException.h"

@implementation LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                   withLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate
     withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey {
  LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(self, context, certificate, privateKey);
  return self;
}

- (LibOrgBouncycastleCryptoTlsCertificate *)getCertificate {
  return certificate_;
}

- (IOSByteArray *)decryptPreMasterSecretWithByteArray:(IOSByteArray *)encryptedPreMasterSecret {
  return LibOrgBouncycastleCryptoTlsTlsRSAUtils_safeDecryptPreMasterSecretWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoParamsRSAKeyParameters_withByteArray_(context_, (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(privateKey_, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]), encryptedPreMasterSecret);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsContext:withLibOrgBouncycastleCryptoTlsCertificate:withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[1].selector = @selector(getCertificate);
  methods[2].selector = @selector(decryptPreMasterSecretWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "context_", "LLibOrgBouncycastleCryptoTlsTlsContext;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "certificate_", "LLibOrgBouncycastleCryptoTlsCertificate;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoTlsTlsContext;LLibOrgBouncycastleCryptoTlsCertificate;LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "decryptPreMasterSecret", "[B", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials = { "DefaultTlsEncryptionCredentials", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 3, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials;
}

@end

void LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  LibOrgBouncycastleCryptoTlsAbstractTlsEncryptionCredentials_init(self);
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
  if ([privateKey isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAKeyParameters class]]) {
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"'privateKey' type not supported: ", [[privateKey java_getClass] getName]));
  }
  self->context_ = context;
  self->certificate_ = certificate;
  self->privateKey_ = privateKey;
}

LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *new_LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, context, certificate, privateKey)
}

LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials *create_LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsCertificate *certificate, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials, initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsCertificate_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_, context, certificate, privateKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDefaultTlsEncryptionCredentials)
