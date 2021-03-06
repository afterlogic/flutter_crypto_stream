//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsECDHKeyExchange.java
//

#include "AbstractTlsKeyExchange.h"
#include "AlertDescription.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "CertificateRequest.h"
#include "ClientCertificateType.h"
#include "ECDomainParameters.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "KeyUsage.h"
#include "PublicKeyFactory.h"
#include "SubjectPublicKeyInfo.h"
#include "TlsAgreementCredentials.h"
#include "TlsContext.h"
#include "TlsCredentials.h"
#include "TlsECCUtils.h"
#include "TlsECDHKeyExchange.h"
#include "TlsECDSASigner.h"
#include "TlsFatalAlert.h"
#include "TlsRSASigner.h"
#include "TlsSigner.h"
#include "TlsSignerCredentials.h"
#include "TlsUtils.h"
#include "X509Certificate.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/ClassCastException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/RuntimeException.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
               withIntArray:(IOSIntArray *)namedCurves
             withShortArray:(IOSShortArray *)clientECPointFormats
             withShortArray:(IOSShortArray *)serverECPointFormats {
  LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
  return self;
}

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context {
  [super init__WithLibOrgBouncycastleCryptoTlsTlsContext:context];
  if (self->tlsSigner_ != nil) {
    [self->tlsSigner_ init__WithLibOrgBouncycastleCryptoTlsTlsContext:context];
  }
}

- (void)skipServerCredentials {
  if (keyExchange_ != LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
}

- (void)processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)serverCertificate {
  if (keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
  if ([((LibOrgBouncycastleCryptoTlsCertificate *) nil_chk(serverCertificate)) isEmpty]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_bad_certificate);
  }
  LibOrgBouncycastleAsn1X509X509Certificate *x509Cert = [serverCertificate getCertificateAtWithInt:0];
  LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo = [((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(x509Cert)) getSubjectPublicKeyInfo];
  @try {
    self->serverPublicKey_ = LibOrgBouncycastleCryptoUtilPublicKeyFactory_createKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
  }
  @catch (JavaLangRuntimeException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_unsupported_certificate, e);
  }
  if (tlsSigner_ == nil) {
    @try {
      self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk(self->serverPublicKey_, [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]));
    }
    @catch (JavaLangClassCastException *e) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_certificate_unknown, e);
    }
    LibOrgBouncycastleCryptoTlsTlsUtils_validateKeyUsageWithLibOrgBouncycastleAsn1X509X509Certificate_withInt_(x509Cert, LibOrgBouncycastleAsn1X509KeyUsage_keyAgreement);
  }
  else {
    if (![tlsSigner_ isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:self->serverPublicKey_]) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_certificate_unknown);
    }
    LibOrgBouncycastleCryptoTlsTlsUtils_validateKeyUsageWithLibOrgBouncycastleAsn1X509X509Certificate_withInt_(x509Cert, LibOrgBouncycastleAsn1X509KeyUsage_digitalSignature);
  }
  [super processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:serverCertificate];
}

- (jboolean)requiresServerKeyExchange {
  switch (keyExchange_) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_ECDSA:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_RSA:
    return true;
    default:
    return false;
  }
}

- (IOSByteArray *)generateServerKeyExchange {
  if (![self requiresServerKeyExchange]) {
    return nil;
  }
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  self->ecAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_generateEphemeralServerKeyExchangeWithJavaSecuritySecureRandom_withIntArray_withShortArray_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], namedCurves_, clientECPointFormats_, buf);
  return [buf toByteArray];
}

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  if (![self requiresServerKeyExchange]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
  LibOrgBouncycastleCryptoParamsECDomainParameters *curve_params = LibOrgBouncycastleCryptoTlsTlsECCUtils_readECParametersWithIntArray_withShortArray_withJavaIoInputStream_(namedCurves_, clientECPointFormats_, input);
  IOSByteArray *point = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(input);
  self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(LibOrgBouncycastleCryptoTlsTlsECCUtils_deserializeECPublicKeyWithShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(clientECPointFormats_, curve_params, point));
}

- (void)validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest {
  if (keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_handshake_failure);
  }
  IOSShortArray *types = [((LibOrgBouncycastleCryptoTlsCertificateRequest *) nil_chk(certificateRequest)) getCertificateTypes];
  for (jint i = 0; i < ((IOSShortArray *) nil_chk(types))->size_; ++i) {
    switch (IOSShortArray_Get(types, i)) {
      case LibOrgBouncycastleCryptoTlsClientCertificateType_rsa_sign:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_dss_sign:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_ecdsa_sign:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_rsa_fixed_ecdh:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_ecdsa_fixed_ecdh:
      break;
      default:
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter);
    }
  }
}

- (void)processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)clientCredentials {
  if (keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  if ([LibOrgBouncycastleCryptoTlsTlsAgreementCredentials_class_() isInstance:clientCredentials]) {
    self->agreementCredentials_ = (id<LibOrgBouncycastleCryptoTlsTlsAgreementCredentials>) cast_check(clientCredentials, LibOrgBouncycastleCryptoTlsTlsAgreementCredentials_class_());
  }
  else if ([LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_() isInstance:clientCredentials]) {
  }
  else {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (void)generateClientKeyExchangeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  if (agreementCredentials_ == nil) {
    self->ecAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_generateEphemeralClientKeyExchangeWithJavaSecuritySecureRandom_withShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], serverECPointFormats_, [((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(ecAgreePublicKey_)) getParameters], output);
  }
}

- (void)processClientCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)clientCertificate {
  if (keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
}

- (void)processClientKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  if (ecAgreePublicKey_ != nil) {
    return;
  }
  IOSByteArray *point = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(input);
  LibOrgBouncycastleCryptoParamsECDomainParameters *curve_params = [((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(self->ecAgreePrivateKey_)) getParameters];
  self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(LibOrgBouncycastleCryptoTlsTlsECCUtils_deserializeECPublicKeyWithShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(serverECPointFormats_, curve_params, point));
}

- (IOSByteArray *)generatePremasterSecret {
  if (agreementCredentials_ != nil) {
    return [agreementCredentials_ generateAgreementWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:ecAgreePublicKey_];
  }
  if (ecAgreePrivateKey_ != nil) {
    return LibOrgBouncycastleCryptoTlsTlsECCUtils_calculateECDHBasicAgreementWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(ecAgreePublicKey_, ecAgreePrivateKey_);
  }
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 11, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 5, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 15, 7, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaUtilVector:withIntArray:withShortArray:withShortArray:);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoTlsTlsContext:);
  methods[2].selector = @selector(skipServerCredentials);
  methods[3].selector = @selector(processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:);
  methods[4].selector = @selector(requiresServerKeyExchange);
  methods[5].selector = @selector(generateServerKeyExchange);
  methods[6].selector = @selector(processServerKeyExchangeWithJavaIoInputStream:);
  methods[7].selector = @selector(validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:);
  methods[8].selector = @selector(processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[9].selector = @selector(generateClientKeyExchangeWithJavaIoOutputStream:);
  methods[10].selector = @selector(processClientCertificateWithLibOrgBouncycastleCryptoTlsCertificate:);
  methods[11].selector = @selector(processClientKeyExchangeWithJavaIoInputStream:);
  methods[12].selector = @selector(generatePremasterSecret);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tlsSigner_", "LLibOrgBouncycastleCryptoTlsTlsSigner;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "namedCurves_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "clientECPointFormats_", "[S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverECPointFormats_", "[S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "agreementCredentials_", "LLibOrgBouncycastleCryptoTlsTlsAgreementCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "ecAgreePrivateKey_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "ecAgreePublicKey_", "LLibOrgBouncycastleCryptoParamsECPublicKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaUtilVector;[I[S[S", "init", "LLibOrgBouncycastleCryptoTlsTlsContext;", "LJavaIoIOException;", "processServerCertificate", "LLibOrgBouncycastleCryptoTlsCertificate;", "processServerKeyExchange", "LJavaIoInputStream;", "validateCertificateRequest", "LLibOrgBouncycastleCryptoTlsCertificateRequest;", "processClientCredentials", "LLibOrgBouncycastleCryptoTlsTlsCredentials;", "generateClientKeyExchange", "LJavaIoOutputStream;", "processClientCertificate", "processClientKeyExchange" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange = { "TlsECDHKeyExchange", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 13, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange;
}

@end

void LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange_initWithInt_withJavaUtilVector_(self, keyExchange, supportedSignatureAlgorithms);
  switch (keyExchange) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_RSA:
    self->tlsSigner_ = new_LibOrgBouncycastleCryptoTlsTlsRSASigner_init();
    break;
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_ECDSA:
    self->tlsSigner_ = new_LibOrgBouncycastleCryptoTlsTlsECDSASigner_init();
    break;
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_RSA:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDH_ECDSA:
    self->tlsSigner_ = nil;
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unsupported key exchange algorithm");
  }
  self->namedCurves_ = namedCurves;
  self->clientECPointFormats_ = clientECPointFormats;
  self->serverECPointFormats_ = serverECPointFormats;
}

LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange, initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
}

LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange, initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange)
