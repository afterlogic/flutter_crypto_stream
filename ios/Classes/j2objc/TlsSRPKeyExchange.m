//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsSRPKeyExchange.java
//

#include "AbstractTlsKeyExchange.h"
#include "AlertDescription.h"
#include "Arrays.h"
#include "AsymmetricKeyParameter.h"
#include "BigIntegers.h"
#include "Certificate.h"
#include "CertificateRequest.h"
#include "CryptoException.h"
#include "DefaultTlsSRPGroupVerifier.h"
#include "Digest.h"
#include "DigestInputBuffer.h"
#include "DigitallySigned.h"
#include "HashAlgorithm.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "KeyUsage.h"
#include "PublicKeyFactory.h"
#include "SRP6Client.h"
#include "SRP6GroupParameters.h"
#include "SRP6Server.h"
#include "SRP6Util.h"
#include "SecurityParameters.h"
#include "ServerSRPParams.h"
#include "SignatureAndHashAlgorithm.h"
#include "Signer.h"
#include "SignerInputBuffer.h"
#include "SubjectPublicKeyInfo.h"
#include "TeeInputStream.h"
#include "TlsContext.h"
#include "TlsCredentials.h"
#include "TlsDSSSigner.h"
#include "TlsFatalAlert.h"
#include "TlsRSASigner.h"
#include "TlsSRPGroupVerifier.h"
#include "TlsSRPKeyExchange.h"
#include "TlsSRPLoginParameters.h"
#include "TlsSRPUtils.h"
#include "TlsSigner.h"
#include "TlsSignerCredentials.h"
#include "TlsUtils.h"
#include "X509Certificate.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange

+ (id<LibOrgBouncycastleCryptoTlsTlsSigner>)createSignerWithInt:(jint)keyExchange {
  return LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_createSignerWithInt_(keyExchange);
}

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
              withByteArray:(IOSByteArray *)identity
              withByteArray:(IOSByteArray *)password {
  LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(self, keyExchange, supportedSignatureAlgorithms, identity, password);
  return self;
}

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier:(id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier>)groupVerifier
              withByteArray:(IOSByteArray *)identity
              withByteArray:(IOSByteArray *)password {
  LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(self, keyExchange, supportedSignatureAlgorithms, groupVerifier, identity, password);
  return self;
}

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
              withByteArray:(IOSByteArray *)identity
withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters:(LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *)loginParameters {
  LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(self, keyExchange, supportedSignatureAlgorithms, identity, loginParameters);
  return self;
}

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context {
  [super init__WithLibOrgBouncycastleCryptoTlsTlsContext:context];
  if (self->tlsSigner_ != nil) {
    [self->tlsSigner_ init__WithLibOrgBouncycastleCryptoTlsTlsContext:context];
  }
}

- (void)skipServerCredentials {
  if (tlsSigner_ != nil) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
  }
}

- (void)processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)serverCertificate {
  if (tlsSigner_ == nil) {
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
  if (![((id<LibOrgBouncycastleCryptoTlsTlsSigner>) nil_chk(tlsSigner_)) isValidPublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:self->serverPublicKey_]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_certificate_unknown);
  }
  LibOrgBouncycastleCryptoTlsTlsUtils_validateKeyUsageWithLibOrgBouncycastleAsn1X509X509Certificate_withInt_(x509Cert, LibOrgBouncycastleAsn1X509KeyUsage_digitalSignature);
  [super processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:serverCertificate];
}

- (void)processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)serverCredentials {
  if ((keyExchange_ == LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP) || !([LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_() isInstance:serverCredentials])) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  [self processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:[((id<LibOrgBouncycastleCryptoTlsTlsCredentials>) nil_chk(serverCredentials)) getCertificate]];
  self->serverCredentials_ = (id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>) cast_check(serverCredentials, LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_());
}

- (jboolean)requiresServerKeyExchange {
  return true;
}

- (IOSByteArray *)generateServerKeyExchange {
  [((LibOrgBouncycastleCryptoAgreementSrpSRP6Server *) nil_chk(srpServer_)) init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:srpGroup_ withJavaMathBigInteger:srpVerifier_ withLibOrgBouncycastleCryptoDigest:LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha1) withJavaSecuritySecureRandom:[((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom]];
  JavaMathBigInteger *B = [((LibOrgBouncycastleCryptoAgreementSrpSRP6Server *) nil_chk(srpServer_)) generateServerCredentials];
  LibOrgBouncycastleCryptoTlsServerSRPParams *srpParams = new_LibOrgBouncycastleCryptoTlsServerSRPParams_initWithJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(srpGroup_)) getN], [((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(srpGroup_)) getG], srpSalt_, B);
  LibOrgBouncycastleCryptoTlsDigestInputBuffer *buf = new_LibOrgBouncycastleCryptoTlsDigestInputBuffer_init();
  [srpParams encodeWithJavaIoOutputStream:buf];
  if (serverCredentials_ != nil) {
    LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getSignatureAndHashAlgorithmWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsTlsSignerCredentials_(context_, serverCredentials_);
    id<LibOrgBouncycastleCryptoDigest> d = LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(signatureAndHashAlgorithm);
    LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters = [((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(d)) updateWithByteArray:((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
    [d updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
    [buf updateDigestWithLibOrgBouncycastleCryptoDigest:d];
    IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[d getDigestSize]];
    [d doFinalWithByteArray:hash_ withInt:0];
    IOSByteArray *signature = [((id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>) nil_chk(serverCredentials_)) generateCertificateSignatureWithByteArray:hash_];
    LibOrgBouncycastleCryptoTlsDigitallySigned *signed_params = new_LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(signatureAndHashAlgorithm, signature);
    [signed_params encodeWithJavaIoOutputStream:buf];
  }
  return [buf toByteArray];
}

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters = [((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
  LibOrgBouncycastleCryptoTlsSignerInputBuffer *buf = nil;
  JavaIoInputStream *teeIn = input;
  if (tlsSigner_ != nil) {
    buf = new_LibOrgBouncycastleCryptoTlsSignerInputBuffer_init();
    teeIn = new_LibOrgBouncycastleUtilIoTeeInputStream_initWithJavaIoInputStream_withJavaIoOutputStream_(input, buf);
  }
  LibOrgBouncycastleCryptoTlsServerSRPParams *srpParams = LibOrgBouncycastleCryptoTlsServerSRPParams_parseWithJavaIoInputStream_(teeIn);
  if (buf != nil) {
    LibOrgBouncycastleCryptoTlsDigitallySigned *signed_params = [self parseSignatureWithJavaIoInputStream:input];
    id<LibOrgBouncycastleCryptoSigner> signer = [self initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:tlsSigner_ withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:[((LibOrgBouncycastleCryptoTlsDigitallySigned *) nil_chk(signed_params)) getAlgorithm] withLibOrgBouncycastleCryptoTlsSecurityParameters:securityParameters];
    [buf updateSignerWithLibOrgBouncycastleCryptoSigner:signer];
    if (![((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer)) verifySignatureWithByteArray:[signed_params getSignature]]) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decrypt_error);
    }
  }
  self->srpGroup_ = new_LibOrgBouncycastleCryptoParamsSRP6GroupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoTlsServerSRPParams *) nil_chk(srpParams)) getN], [srpParams getG]);
  if (![((id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier>) nil_chk(groupVerifier_)) acceptWithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:srpGroup_]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_insufficient_security);
  }
  self->srpSalt_ = [srpParams getS];
  @try {
    self->srpPeerCredentials_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_validatePublicValueWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(srpGroup_)) getN], [srpParams getB]);
  }
  @catch (LibOrgBouncycastleCryptoCryptoException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter, e);
  }
  [((LibOrgBouncycastleCryptoAgreementSrpSRP6Client *) nil_chk(self->srpClient_)) init__WithLibOrgBouncycastleCryptoParamsSRP6GroupParameters:srpGroup_ withLibOrgBouncycastleCryptoDigest:LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha1) withJavaSecuritySecureRandom:[((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom]];
}

- (void)validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
}

- (void)processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)clientCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

- (void)generateClientKeyExchangeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  JavaMathBigInteger *A = [((LibOrgBouncycastleCryptoAgreementSrpSRP6Client *) nil_chk(srpClient_)) generateClientCredentialsWithByteArray:srpSalt_ withByteArray:identity_ withByteArray:password_];
  LibOrgBouncycastleCryptoTlsTlsSRPUtils_writeSRPParameterWithJavaMathBigInteger_withJavaIoOutputStream_(A, output);
  ((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters]))->srpIdentity_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(identity_);
}

- (void)processClientKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  @try {
    self->srpPeerCredentials_ = LibOrgBouncycastleCryptoAgreementSrpSRP6Util_validatePublicValueWithJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleCryptoParamsSRP6GroupParameters *) nil_chk(srpGroup_)) getN], LibOrgBouncycastleCryptoTlsTlsSRPUtils_readSRPParameterWithJavaIoInputStream_(input));
  }
  @catch (LibOrgBouncycastleCryptoCryptoException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter, e);
  }
  ((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters]))->srpIdentity_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(identity_);
}

- (IOSByteArray *)generatePremasterSecret {
  @try {
    JavaMathBigInteger *S = srpServer_ != nil ? [srpServer_ calculateSecretWithJavaMathBigInteger:srpPeerCredentials_] : [((LibOrgBouncycastleCryptoAgreementSrpSRP6Client *) nil_chk(srpClient_)) calculateSecretWithJavaMathBigInteger:srpPeerCredentials_];
    return LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(S);
  }
  @catch (LibOrgBouncycastleCryptoCryptoException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter, e);
  }
}

- (id<LibOrgBouncycastleCryptoSigner>)initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:(id<LibOrgBouncycastleCryptoTlsTlsSigner>)tlsSigner
                                  withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                         withLibOrgBouncycastleCryptoTlsSecurityParameters:(LibOrgBouncycastleCryptoTlsSecurityParameters *)securityParameters {
  id<LibOrgBouncycastleCryptoSigner> signer = [((id<LibOrgBouncycastleCryptoTlsTlsSigner>) nil_chk(tlsSigner)) createVerifyerWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:self->serverPublicKey_];
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer)) updateWithByteArray:((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
  [signer updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
  return signer;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsSigner;", 0xc, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 11, 7, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 15, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 16, 11, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 18, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 19, 13, 7, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 7, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoSigner;", 0x4, 20, 21, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(createSignerWithInt:);
  methods[1].selector = @selector(initWithInt:withJavaUtilVector:withByteArray:withByteArray:);
  methods[2].selector = @selector(initWithInt:withJavaUtilVector:withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier:withByteArray:withByteArray:);
  methods[3].selector = @selector(initWithInt:withJavaUtilVector:withByteArray:withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters:);
  methods[4].selector = @selector(init__WithLibOrgBouncycastleCryptoTlsTlsContext:);
  methods[5].selector = @selector(skipServerCredentials);
  methods[6].selector = @selector(processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:);
  methods[7].selector = @selector(processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[8].selector = @selector(requiresServerKeyExchange);
  methods[9].selector = @selector(generateServerKeyExchange);
  methods[10].selector = @selector(processServerKeyExchangeWithJavaIoInputStream:);
  methods[11].selector = @selector(validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:);
  methods[12].selector = @selector(processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[13].selector = @selector(generateClientKeyExchangeWithJavaIoOutputStream:);
  methods[14].selector = @selector(processClientKeyExchangeWithJavaIoInputStream:);
  methods[15].selector = @selector(generatePremasterSecret);
  methods[16].selector = @selector(initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:withLibOrgBouncycastleCryptoTlsSecurityParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tlsSigner_", "LLibOrgBouncycastleCryptoTlsTlsSigner;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "groupVerifier_", "LLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "identity_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "password_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpGroup_", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpClient_", "LLibOrgBouncycastleCryptoAgreementSrpSRP6Client;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpServer_", "LLibOrgBouncycastleCryptoAgreementSrpSRP6Server;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpPeerCredentials_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpVerifier_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpSalt_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverCredentials_", "LLibOrgBouncycastleCryptoTlsTlsSignerCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "createSigner", "I", "ILJavaUtilVector;[B[B", "ILJavaUtilVector;LLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier;[B[B", "ILJavaUtilVector;[BLLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters;", "init", "LLibOrgBouncycastleCryptoTlsTlsContext;", "LJavaIoIOException;", "processServerCertificate", "LLibOrgBouncycastleCryptoTlsCertificate;", "processServerCredentials", "LLibOrgBouncycastleCryptoTlsTlsCredentials;", "processServerKeyExchange", "LJavaIoInputStream;", "validateCertificateRequest", "LLibOrgBouncycastleCryptoTlsCertificateRequest;", "processClientCredentials", "generateClientKeyExchange", "LJavaIoOutputStream;", "processClientKeyExchange", "initVerifyer", "LLibOrgBouncycastleCryptoTlsTlsSigner;LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;LLibOrgBouncycastleCryptoTlsSecurityParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange = { "TlsSRPKeyExchange", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 17, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange;
}

@end

id<LibOrgBouncycastleCryptoTlsTlsSigner> LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_createSignerWithInt_(jint keyExchange) {
  LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initialize();
  switch (keyExchange) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP:
    return nil;
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_RSA:
    return new_LibOrgBouncycastleCryptoTlsTlsRSASigner_init();
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_DSS:
    return new_LibOrgBouncycastleCryptoTlsTlsDSSSigner_init();
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unsupported key exchange algorithm");
  }
}

void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password) {
  LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(self, keyExchange, supportedSignatureAlgorithms, new_LibOrgBouncycastleCryptoTlsDefaultTlsSRPGroupVerifier_init(), identity, password);
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withByteArray_withByteArray_, keyExchange, supportedSignatureAlgorithms, identity, password)
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, IOSByteArray *password) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withByteArray_withByteArray_, keyExchange, supportedSignatureAlgorithms, identity, password)
}

void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password) {
  LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange_initWithInt_withJavaUtilVector_(self, keyExchange, supportedSignatureAlgorithms);
  self->serverPublicKey_ = nil;
  self->srpGroup_ = nil;
  self->srpClient_ = nil;
  self->srpServer_ = nil;
  self->srpPeerCredentials_ = nil;
  self->srpVerifier_ = nil;
  self->srpSalt_ = nil;
  self->serverCredentials_ = nil;
  self->tlsSigner_ = LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_createSignerWithInt_(keyExchange);
  self->groupVerifier_ = groupVerifier;
  self->identity_ = identity;
  self->password_ = password;
  self->srpClient_ = new_LibOrgBouncycastleCryptoAgreementSrpSRP6Client_init();
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_, keyExchange, supportedSignatureAlgorithms, groupVerifier, identity, password)
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, id<LibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier> groupVerifier, IOSByteArray *identity, IOSByteArray *password) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsSRPGroupVerifier_withByteArray_withByteArray_, keyExchange, supportedSignatureAlgorithms, groupVerifier, identity, password)
}

void LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters) {
  LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange_initWithInt_withJavaUtilVector_(self, keyExchange, supportedSignatureAlgorithms);
  self->serverPublicKey_ = nil;
  self->srpGroup_ = nil;
  self->srpClient_ = nil;
  self->srpServer_ = nil;
  self->srpPeerCredentials_ = nil;
  self->srpVerifier_ = nil;
  self->srpSalt_ = nil;
  self->serverCredentials_ = nil;
  self->tlsSigner_ = LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_createSignerWithInt_(keyExchange);
  self->identity_ = identity;
  self->srpServer_ = new_LibOrgBouncycastleCryptoAgreementSrpSRP6Server_init();
  self->srpGroup_ = [((LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *) nil_chk(loginParameters)) getGroup];
  self->srpVerifier_ = [loginParameters getVerifier];
  self->srpSalt_ = [loginParameters getSalt];
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_, keyExchange, supportedSignatureAlgorithms, identity, loginParameters)
}

LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSByteArray *identity, LibOrgBouncycastleCryptoTlsTlsSRPLoginParameters *loginParameters) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange, initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_, keyExchange, supportedSignatureAlgorithms, identity, loginParameters)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange)
