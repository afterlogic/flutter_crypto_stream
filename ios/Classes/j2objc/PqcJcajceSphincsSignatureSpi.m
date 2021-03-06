//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/sphincs/PqcJcajceSphincsSignatureSpi.java
//

#include "ASN1ObjectIdentifier.h"
#include "BCSphincs256PrivateKey.h"
#include "BCSphincs256PublicKey.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NISTObjectIdentifiers.h"
#include "PqcJcajceSphincsSignatureSpi.h"
#include "SHA3Digest.h"
#include "SHA512Digest.h"
#include "SHA512tDigest.h"
#include "SPHINCS256Signer.h"
#include "java/lang/Exception.h"
#include "java/lang/UnsupportedOperationException.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/SecureRandom.h"
#include "java/security/SignatureException.h"
#include "java/security/SignatureSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest_;
  id<LibOrgBouncycastleCryptoDigest> digest_;
  LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, treeDigest_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, signer_, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, random_, JavaSecuritySecureRandom *)

@implementation LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
        withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)treeDigest
withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer:(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *)signer {
  LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(self, digest, treeDigest, signer);
  return self;
}

- (void)engineInitVerifyWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)publicKey {
  if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PublicKey class]]) {
    LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PublicKey *key = (LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PublicKey *) publicKey;
    if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(treeDigest_)) isEqual:[((LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PublicKey *) nil_chk(key)) getTreeDigest]]) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$@", @"SPHINCS-256 signature for tree digest: ", [key getTreeDigest]));
    }
    id<LibOrgBouncycastleCryptoCipherParameters> param = [key getKeyParams];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
    [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *) nil_chk(signer_)) init__WithBoolean:false withLibOrgBouncycastleCryptoCipherParameters:param];
  }
  else {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"unknown public key passed to SPHINCS-256");
  }
}

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey
                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->random_ = random;
  [self engineInitSignWithJavaSecurityPrivateKey:privateKey];
}

- (void)engineInitSignWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey {
  if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey class]]) {
    LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *key = (LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *) privateKey;
    if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(treeDigest_)) isEqual:[((LibOrgBouncycastlePqcJcajceProviderSphincsBCSphincs256PrivateKey *) nil_chk(key)) getTreeDigest]]) {
      @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$@", @"SPHINCS-256 signature for tree digest: ", [key getTreeDigest]));
    }
    id<LibOrgBouncycastleCryptoCipherParameters> param = [key getKeyParams];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) reset];
    [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *) nil_chk(signer_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:param];
  }
  else {
    @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"unknown private key passed to SPHINCS-256");
  }
}

- (void)engineUpdateWithByte:(jbyte)b {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:b];
}

- (void)engineUpdateWithByteArray:(IOSByteArray *)b
                          withInt:(jint)off
                          withInt:(jint)len {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:b withInt:off withInt:len];
}

- (IOSByteArray *)engineSign {
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
  @try {
    IOSByteArray *sig = [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *) nil_chk(signer_)) generateSignatureWithByteArray:hash_];
    return sig;
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_([e description]);
  }
}

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes {
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:hash_ withInt:0];
  return [((LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *) nil_chk(signer_)) verifySignatureWithByteArray:hash_ withByteArray:sigBytes];
}

- (void)engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

- (void)engineSetParameterWithNSString:(NSString *)param
                                withId:(id)value {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

- (id)engineGetParameterWithNSString:(NSString *)param {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"engineSetParameter unsupported");
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 5, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 6, 3, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 8, 9, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 10, 9, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 9, -1, -1, -1 },
    { NULL, "Z", 0x4, 11, 12, 9, -1, -1, -1 },
    { NULL, "V", 0x4, 13, 14, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 13, 15, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x4, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer:);
  methods[1].selector = @selector(engineInitVerifyWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(engineInitSignWithJavaSecurityPrivateKey:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(engineInitSignWithJavaSecurityPrivateKey:);
  methods[4].selector = @selector(engineUpdateWithByte:);
  methods[5].selector = @selector(engineUpdateWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(engineSign);
  methods[7].selector = @selector(engineVerifyWithByteArray:);
  methods[8].selector = @selector(engineSetParameterWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[9].selector = @selector(engineSetParameterWithNSString:withId:);
  methods[10].selector = @selector(engineGetParameterWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "treeDigest_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signer_", "LLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer;", "engineInitVerify", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "engineInitSign", "LJavaSecurityPrivateKey;LJavaSecuritySecureRandom;", "LJavaSecurityPrivateKey;", "engineUpdate", "B", "LJavaSecuritySignatureException;", "[BII", "engineVerify", "[B", "engineSetParameter", "LJavaSecuritySpecAlgorithmParameterSpec;", "LNSString;LNSObject;", "engineGetParameter", "LNSString;", "LLibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512;LLibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi = { "PqcJcajceSphincsSignatureSpi", "lib.org.bouncycastle.pqc.jcajce.provider.sphincs", ptrTable, methods, fields, 7, 0x1, 11, 4, -1, 18, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *self, id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer) {
  JavaSecuritySignatureSpi_init(self);
  self->digest_ = digest;
  self->treeDigest_ = treeDigest;
  self->signer_ = signer;
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_, digest, treeDigest, signer)
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(id<LibOrgBouncycastleCryptoDigest> digest, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *treeDigest, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer *signer) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi, initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_, digest, treeDigest, signer)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi)

@implementation LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 = { "withSha512", "lib.org.bouncycastle.pqc.jcajce.provider.sphincs", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512;
}

@end

void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *self) {
  LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(self, new_LibOrgBouncycastleCryptoDigestsSHA512Digest_init(), JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256), new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsSHA512tDigest_initWithInt_(256), new_LibOrgBouncycastleCryptoDigestsSHA512Digest_init()));
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512, init)
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512 *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha512)

@implementation LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 = { "withSha3_512", "lib.org.bouncycastle.pqc.jcajce.provider.sphincs", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512;
}

@end

void LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *self) {
  LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_(self, new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(512), JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256), new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Signer_initWithLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(256), new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(512)));
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *new_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512, init)
}

LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512 *create_LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderSphincsPqcJcajceSphincsSignatureSpi_withSha3_512)
