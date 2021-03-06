//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/PqcJcajceXMSS.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricAlgorithmProvider.h"
#include "BCObjectIdentifiers.h"
#include "ConfigurableProvider.h"
#include "J2ObjC_source.h"
#include "PQCObjectIdentifiers.h"
#include "PqcJcajceXMSS.h"
#include "XMSSKeyFactorySpi.h"
#include "XMSSMTKeyFactorySpi.h"

inline NSString *LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_get_PREFIX(void);
static NSString *LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX = @"lib.org.bouncycastle.pqc.jcajce.provider.xmss.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS, PREFIX, NSString *)

@implementation LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_init(self);
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
  static const void *ptrTable[] = { &LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, "LLibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS = { "PqcJcajceXMSS", "lib.org.bouncycastle.pqc.jcajce.provider", ptrTable, methods, fields, 7, 0x1, 1, 1, -1, 1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS;
}

@end

void LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_init(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS *new_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS, init)
}

LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS *create_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS)

@implementation LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"KeyFactory.XMSS" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.XMSS" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSKeyPairGeneratorSpi")];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSS-SHA256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withSha256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHA256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSS-SHAKE128" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withShake128") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHAKE128)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSS-SHA512" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withSha512") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHA512)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSS-SHAKE256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withShake256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHAKE256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA256" withNSString:@"XMSS-SHA256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withSha256andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHA256ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHAKE128" withNSString:@"XMSS-SHAKE128" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withShake128andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHAKE128ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA512" withNSString:@"XMSS-SHA512" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withSha512andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHA512ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHAKE256" withNSString:@"XMSS-SHAKE256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSSignatureSpi$withShake256andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_SHAKE256ph)];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA256WITHXMSS" withNSString:@"SHA256WITHXMSS-SHA256"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHAKE128WITHXMSS" withNSString:@"SHAKE128WITHXMSS-SHAKE128"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA512WITHXMSS" withNSString:@"SHA512WITHXMSS-SHA512"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHAKE256WITHXMSS" withNSString:@"SHAKE256WITHXMSS-SHAKE256"];
  [provider addAlgorithmWithNSString:@"KeyFactory.XMSSMT" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.XMSSMT" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTKeyPairGeneratorSpi")];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSSMT-SHA256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withSha256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHA256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSSMT-SHAKE128" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withShake128") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHAKE128)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSSMT-SHA512" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withSha512") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHA512)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"XMSSMT-SHAKE256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withShake256") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHAKE256)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA256" withNSString:@"XMSSMT-SHA256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withSha256andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHA256ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHAKE128" withNSString:@"XMSSMT-SHAKE128" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withShake128andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHAKE128ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHA512" withNSString:@"XMSSMT-SHA512" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withSha512andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHA512ph)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"SHAKE256" withNSString:@"XMSSMT-SHAKE256" withNSString:JreStrcat("$$", LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_PREFIX, @"XMSSMTSignatureSpi$withShake256andPrehash") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1BcBCObjectIdentifiers, xmss_mt_SHAKE256ph)];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA256WITHXMSSMT" withNSString:@"SHA256WITHXMSSMT-SHA256"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHAKE128WITHXMSSMT" withNSString:@"SHAKE128WITHXMSSMT-SHAKE128"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHA512WITHXMSSMT" withNSString:@"SHA512WITHXMSSMT-SHA512"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.SHAKE256WITHXMSSMT" withNSString:@"SHAKE256WITHXMSSMT-SHAKE256"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss) withNSString:@"XMSS" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderXmssXMSSKeyFactorySpi_init()];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss_mt) withNSString:@"XMSSMT" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyFactorySpi_init()];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings = { "Mappings", "lib.org.bouncycastle.pqc.jcajce.provider", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings;
}

@end

void LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings_init(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings *new_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings, init)
}

LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings *create_LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderPqcJcajceXMSS_Mappings)
