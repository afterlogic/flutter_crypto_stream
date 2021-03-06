//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsPSKKeyExchange.java
//

#include "AbstractTlsKeyExchange.h"
#include "AlertDescription.h"
#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "CertificateRequest.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "DefaultTlsDHVerifier.h"
#include "ECDomainParameters.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "KeyUsage.h"
#include "PublicKeyFactory.h"
#include "RSAKeyParameters.h"
#include "SecurityParameters.h"
#include "Streams.h"
#include "SubjectPublicKeyInfo.h"
#include "TlsContext.h"
#include "TlsCredentials.h"
#include "TlsDHUtils.h"
#include "TlsDHVerifier.h"
#include "TlsECCUtils.h"
#include "TlsEncryptionCredentials.h"
#include "TlsFatalAlert.h"
#include "TlsPSKIdentity.h"
#include "TlsPSKIdentityManager.h"
#include "TlsPSKKeyExchange.h"
#include "TlsRSAUtils.h"
#include "TlsUtils.h"
#include "X509Certificate.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
withLibOrgBouncycastleCryptoTlsTlsPSKIdentity:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>)pskIdentity
withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager
withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParameters
               withIntArray:(IOSIntArray *)namedCurves
             withShortArray:(IOSShortArray *)clientECPointFormats
             withShortArray:(IOSShortArray *)serverECPointFormats {
  LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats);
  return self;
}

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
withLibOrgBouncycastleCryptoTlsTlsPSKIdentity:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>)pskIdentity
withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager
withLibOrgBouncycastleCryptoTlsTlsDHVerifier:(id<LibOrgBouncycastleCryptoTlsTlsDHVerifier>)dhVerifier
withLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)dhParameters
               withIntArray:(IOSIntArray *)namedCurves
             withShortArray:(IOSShortArray *)clientECPointFormats
             withShortArray:(IOSShortArray *)serverECPointFormats {
  LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhVerifier, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats);
  return self;
}

- (void)skipServerCredentials {
  if (keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
}

- (void)processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)serverCredentials {
  if (!([LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials_class_() isInstance:serverCredentials])) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  [self processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:[((id<LibOrgBouncycastleCryptoTlsTlsCredentials>) nil_chk(serverCredentials)) getCertificate]];
  self->serverCredentials_ = (id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>) cast_check(serverCredentials, LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials_class_());
}

- (IOSByteArray *)generateServerKeyExchange {
  self->psk_identity_hint_ = [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>) nil_chk(pskIdentityManager_)) getHint];
  if (self->psk_identity_hint_ == nil && ![self requiresServerKeyExchange]) {
    return nil;
  }
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  if (self->psk_identity_hint_ == nil) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(JreLoadStatic(LibOrgBouncycastleCryptoTlsTlsUtils, EMPTY_BYTES), buf);
  }
  else {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(self->psk_identity_hint_, buf);
  }
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK) {
    if (self->dhParameters_ == nil) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
    }
    self->dhAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsDHUtils_generateEphemeralServerKeyExchangeWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], self->dhParameters_, buf);
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK) {
    self->ecAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_generateEphemeralServerKeyExchangeWithJavaSecuritySecureRandom_withIntArray_withShortArray_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], namedCurves_, clientECPointFormats_, buf);
  }
  return [buf toByteArray];
}

- (void)processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)serverCertificate {
  if (keyExchange_ != LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK) {
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
  if ([((LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(self->serverPublicKey_)) isPrivate]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  self->rsaServerPublicKey_ = [self validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(self->serverPublicKey_, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class])];
  LibOrgBouncycastleCryptoTlsTlsUtils_validateKeyUsageWithLibOrgBouncycastleAsn1X509X509Certificate_withInt_(x509Cert, LibOrgBouncycastleAsn1X509KeyUsage_keyEncipherment);
  [super processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:serverCertificate];
}

- (jboolean)requiresServerKeyExchange {
  switch (keyExchange_) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK:
    return true;
    default:
    return false;
  }
}

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  self->psk_identity_hint_ = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK) {
    self->dhParameters_ = LibOrgBouncycastleCryptoTlsTlsDHUtils_receiveDHParametersWithLibOrgBouncycastleCryptoTlsTlsDHVerifier_withJavaIoInputStream_(dhVerifier_, input);
    self->dhAgreePublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoTlsTlsDHUtils_readDHParameterWithJavaIoInputStream_(input), dhParameters_);
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK) {
    LibOrgBouncycastleCryptoParamsECDomainParameters *ecParams = LibOrgBouncycastleCryptoTlsTlsECCUtils_readECParametersWithIntArray_withShortArray_withJavaIoInputStream_(namedCurves_, clientECPointFormats_, input);
    IOSByteArray *point = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(input);
    self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(LibOrgBouncycastleCryptoTlsTlsECCUtils_deserializeECPublicKeyWithShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(clientECPointFormats_, ecParams, point));
  }
}

- (void)validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
}

- (void)processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)clientCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

- (void)generateClientKeyExchangeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  if (psk_identity_hint_ == nil) {
    [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>) nil_chk(pskIdentity_)) skipIdentityHint];
  }
  else {
    [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>) nil_chk(pskIdentity_)) notifyIdentityHintWithByteArray:psk_identity_hint_];
  }
  IOSByteArray *psk_identity = [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>) nil_chk(pskIdentity_)) getPSKIdentity];
  if (psk_identity == nil) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  self->psk_ = [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity>) nil_chk(pskIdentity_)) getPSK];
  if (psk_ == nil) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(psk_identity, output);
  ((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters]))->pskIdentity_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(psk_identity);
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK) {
    self->dhAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsDHUtils_generateEphemeralClientKeyExchangeWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoParamsDHParameters_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], dhParameters_, output);
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK) {
    self->ecAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_generateEphemeralClientKeyExchangeWithJavaSecuritySecureRandom_withShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], serverECPointFormats_, [((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(ecAgreePublicKey_)) getParameters], output);
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK) {
    self->premasterSecret_ = LibOrgBouncycastleCryptoTlsTlsRSAUtils_generateEncryptedPreMasterSecretWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoParamsRSAKeyParameters_withJavaIoOutputStream_(context_, self->rsaServerPublicKey_, output);
  }
}

- (void)processClientKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  IOSByteArray *psk_identity = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
  self->psk_ = [((id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>) nil_chk(pskIdentityManager_)) getPSKWithByteArray:psk_identity];
  if (psk_ == nil) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unknown_psk_identity);
  }
  ((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters]))->pskIdentity_ = psk_identity;
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK) {
    self->dhAgreePublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(LibOrgBouncycastleCryptoTlsTlsDHUtils_readDHParameterWithJavaIoInputStream_(input), dhParameters_);
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK) {
    IOSByteArray *point = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(input);
    LibOrgBouncycastleCryptoParamsECDomainParameters *curve_params = [((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(self->ecAgreePrivateKey_)) getParameters];
    self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(LibOrgBouncycastleCryptoTlsTlsECCUtils_deserializeECPublicKeyWithShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(serverECPointFormats_, curve_params, point));
  }
  else if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK) {
    IOSByteArray *encryptedPreMasterSecret;
    if (LibOrgBouncycastleCryptoTlsTlsUtils_isSSLWithLibOrgBouncycastleCryptoTlsTlsContext_(context_)) {
      encryptedPreMasterSecret = LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(input);
    }
    else {
      encryptedPreMasterSecret = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
    }
    self->premasterSecret_ = [((id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>) nil_chk(serverCredentials_)) decryptPreMasterSecretWithByteArray:encryptedPreMasterSecret];
  }
}

- (IOSByteArray *)generatePremasterSecret {
  IOSByteArray *other_secret = [self generateOtherSecretWithInt:((IOSByteArray *) nil_chk(psk_))->size_];
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_initWithInt_(4 + ((IOSByteArray *) nil_chk(other_secret))->size_ + ((IOSByteArray *) nil_chk(psk_))->size_);
  LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(other_secret, buf);
  LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(psk_, buf);
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(psk_, (jbyte) 0);
  self->psk_ = nil;
  return [buf toByteArray];
}

- (IOSByteArray *)generateOtherSecretWithInt:(jint)pskLength {
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK) {
    if (dhAgreePrivateKey_ != nil) {
      return LibOrgBouncycastleCryptoTlsTlsDHUtils_calculateDHBasicAgreementWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(dhAgreePublicKey_, dhAgreePrivateKey_);
    }
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK) {
    if (ecAgreePrivateKey_ != nil) {
      return LibOrgBouncycastleCryptoTlsTlsECCUtils_calculateECDHBasicAgreementWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(ecAgreePublicKey_, ecAgreePrivateKey_);
    }
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  if (self->keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK) {
    return self->premasterSecret_;
  }
  return [IOSByteArray newArrayWithLength:pskLength];
}

- (LibOrgBouncycastleCryptoParamsRSAKeyParameters *)validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key {
  if (![((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key)) getExponent])) isProbablePrimeWithInt:2]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter);
  }
  return key;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 2, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 2, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 4, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 8, 2, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "[B", 0x4, 15, 16, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", 0x4, 17, 18, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaUtilVector:withLibOrgBouncycastleCryptoTlsTlsPSKIdentity:withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:withLibOrgBouncycastleCryptoParamsDHParameters:withIntArray:withShortArray:withShortArray:);
  methods[1].selector = @selector(initWithInt:withJavaUtilVector:withLibOrgBouncycastleCryptoTlsTlsPSKIdentity:withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:withLibOrgBouncycastleCryptoTlsTlsDHVerifier:withLibOrgBouncycastleCryptoParamsDHParameters:withIntArray:withShortArray:withShortArray:);
  methods[2].selector = @selector(skipServerCredentials);
  methods[3].selector = @selector(processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[4].selector = @selector(generateServerKeyExchange);
  methods[5].selector = @selector(processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:);
  methods[6].selector = @selector(requiresServerKeyExchange);
  methods[7].selector = @selector(processServerKeyExchangeWithJavaIoInputStream:);
  methods[8].selector = @selector(validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:);
  methods[9].selector = @selector(processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[10].selector = @selector(generateClientKeyExchangeWithJavaIoOutputStream:);
  methods[11].selector = @selector(processClientKeyExchangeWithJavaIoInputStream:);
  methods[12].selector = @selector(generatePremasterSecret);
  methods[13].selector = @selector(generateOtherSecretWithInt:);
  methods[14].selector = @selector(validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pskIdentity_", "LLibOrgBouncycastleCryptoTlsTlsPSKIdentity;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "pskIdentityManager_", "LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "dhVerifier_", "LLibOrgBouncycastleCryptoTlsTlsDHVerifier;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "dhParameters_", "LLibOrgBouncycastleCryptoParamsDHParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "namedCurves_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "clientECPointFormats_", "[S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverECPointFormats_", "[S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "psk_identity_hint_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "psk_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "dhAgreePrivateKey_", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "dhAgreePublicKey_", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "ecAgreePrivateKey_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "ecAgreePublicKey_", "LLibOrgBouncycastleCryptoParamsECPublicKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "rsaServerPublicKey_", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverCredentials_", "LLibOrgBouncycastleCryptoTlsTlsEncryptionCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "premasterSecret_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaUtilVector;LLibOrgBouncycastleCryptoTlsTlsPSKIdentity;LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;LLibOrgBouncycastleCryptoParamsDHParameters;[I[S[S", "ILJavaUtilVector;LLibOrgBouncycastleCryptoTlsTlsPSKIdentity;LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;LLibOrgBouncycastleCryptoTlsTlsDHVerifier;LLibOrgBouncycastleCryptoParamsDHParameters;[I[S[S", "LJavaIoIOException;", "processServerCredentials", "LLibOrgBouncycastleCryptoTlsTlsCredentials;", "processServerCertificate", "LLibOrgBouncycastleCryptoTlsCertificate;", "processServerKeyExchange", "LJavaIoInputStream;", "validateCertificateRequest", "LLibOrgBouncycastleCryptoTlsCertificateRequest;", "processClientCredentials", "generateClientKeyExchange", "LJavaIoOutputStream;", "processClientKeyExchange", "generateOtherSecret", "I", "validateRSAPublicKey", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange = { "TlsPSKKeyExchange", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 15, 17, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange;
}

@end

void LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, new_LibOrgBouncycastleCryptoTlsDefaultTlsDHVerifier_init(), dhParameters, namedCurves, clientECPointFormats, serverECPointFormats);
}

LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats)
}

LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats)
}

void LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, id<LibOrgBouncycastleCryptoTlsTlsDHVerifier> dhVerifier, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange_initWithInt_withJavaUtilVector_(self, keyExchange, supportedSignatureAlgorithms);
  self->psk_identity_hint_ = nil;
  self->psk_ = nil;
  self->dhAgreePrivateKey_ = nil;
  self->dhAgreePublicKey_ = nil;
  self->ecAgreePrivateKey_ = nil;
  self->ecAgreePublicKey_ = nil;
  self->serverPublicKey_ = nil;
  self->rsaServerPublicKey_ = nil;
  self->serverCredentials_ = nil;
  switch (keyExchange) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK:
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unsupported key exchange algorithm");
  }
  self->pskIdentity_ = pskIdentity;
  self->pskIdentityManager_ = pskIdentityManager;
  self->dhVerifier_ = dhVerifier;
  self->dhParameters_ = dhParameters;
  self->namedCurves_ = namedCurves;
  self->clientECPointFormats_ = clientECPointFormats;
  self->serverECPointFormats_ = serverECPointFormats;
}

LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, id<LibOrgBouncycastleCryptoTlsTlsDHVerifier> dhVerifier, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhVerifier, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats)
}

LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentity> pskIdentity, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager, id<LibOrgBouncycastleCryptoTlsTlsDHVerifier> dhVerifier, LibOrgBouncycastleCryptoParamsDHParameters *dhParameters, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, pskIdentity, pskIdentityManager, dhVerifier, dhParameters, namedCurves, clientECPointFormats, serverECPointFormats)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange)
