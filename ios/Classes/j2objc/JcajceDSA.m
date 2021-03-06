//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/JcajceDSA.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricAlgorithmProvider.h"
#include "AsymmetricKeyInfoConverter.h"
#include "ConfigurableProvider.h"
#include "DSAUtil.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "JcajceDSA.h"
#include "JcajceDsaKeyFactorySpi.h"
#include "NISTObjectIdentifiers.h"

inline NSString *LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX = @"lib.org.bouncycastle.jcajce.provider.asymmetric.dsa.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_init(self);
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
  static const J2ObjcFieldInfo fields[] = {
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 0, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, "LLibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA = { "JcajceDSA", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, fields, 7, 0x1, 1, 1, -1, 1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_init(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA *new_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA *create_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"AlgorithmParameters.DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"DsaAlgorithmParametersSpi")];
  [provider addAlgorithmWithNSString:@"AlgorithmParameterGenerator.DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"DsaAlgorithmParameterGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDsaKeyPairGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"KeyFactory.DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDsaKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"Signature.DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$stdDSA")];
  [provider addAlgorithmWithNSString:@"Signature.NONEWITHDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$noneDSA")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.RAWDSA" withNSString:@"NONEWITHDSA"];
  [provider addAlgorithmWithNSString:@"Signature.DETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA")];
  [provider addAlgorithmWithNSString:@"Signature.SHA1WITHDETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA")];
  [provider addAlgorithmWithNSString:@"Signature.SHA224WITHDETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA224")];
  [provider addAlgorithmWithNSString:@"Signature.SHA256WITHDETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA256")];
  [provider addAlgorithmWithNSString:@"Signature.SHA384WITHDETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA384")];
  [provider addAlgorithmWithNSString:@"Signature.SHA512WITHDETDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA512")];
  [provider addAlgorithmWithNSString:@"Signature.DDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA")];
  [provider addAlgorithmWithNSString:@"Signature.SHA1WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA")];
  [provider addAlgorithmWithNSString:@"Signature.SHA224WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA224")];
  [provider addAlgorithmWithNSString:@"Signature.SHA256WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA256")];
  [provider addAlgorithmWithNSString:@"Signature.SHA384WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA384")];
  [provider addAlgorithmWithNSString:@"Signature.SHA512WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSA512")];
  [provider addAlgorithmWithNSString:@"Signature.SHA3-224WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSASha3_224")];
  [provider addAlgorithmWithNSString:@"Signature.SHA3-256WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSASha3_256")];
  [provider addAlgorithmWithNSString:@"Signature.SHA3-384WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSASha3_384")];
  [provider addAlgorithmWithNSString:@"Signature.SHA3-512WITHDDSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$detDSASha3_512")];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA224" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsa224") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, dsa_with_sha224)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA256" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsa256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, dsa_with_sha256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA384" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsa384") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, dsa_with_sha384)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA512" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsa512") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, dsa_with_sha512)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA3-224" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsaSha3_224") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_dsa_with_sha3_224)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA3-256" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsaSha3_256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_dsa_with_sha3_256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA3-384" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsaSha3_384") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_dsa_with_sha3_384)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA3-512" withNSString:@"DSA" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_PREFIX, @"JcajceDSASigner$dsaSha3_512") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_dsa_with_sha3_512)];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA/DSA" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA1withDSA" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA1WITHDSA" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.DSAwithSHA1" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.DSAWITHSHA1" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA1WithDSA" withNSString:@"JcajceDSA"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.DSAWithSHA1" withNSString:@"JcajceDSA"];
  id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter> keyFact = new_LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricDsaDSAUtil, dsaOids)))->size_; i++) {
    [provider addAlgorithmWithNSString:JreStrcat("$@", @"Alg.Alias.Signature.", IOSObjectArray_Get(JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricDsaDSAUtil, dsaOids), i)) withNSString:@"JcajceDSA"];
    [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:IOSObjectArray_Get(JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricDsaDSAUtil, dsaOids), i) withNSString:@"JcajceDSA" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:keyFact];
    [self registerOidAlgorithmParameterGeneratorWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:IOSObjectArray_Get(JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricDsaDSAUtil, dsaOids), i) withNSString:@"JcajceDSA"];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricJcajceDSA_Mappings)
