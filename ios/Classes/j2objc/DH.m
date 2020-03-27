//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/DH.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricAlgorithmProvider.h"
#include "ConfigurableProvider.h"
#include "DH.h"
#include "J2ObjC_source.h"
#include "JcajceDhKeyFactorySpi.h"
#include "PKCSObjectIdentifiers.h"
#include "X9ObjectIdentifiers.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"

inline NSString *LibOrgBouncycastleJcajceProviderAsymmetricDH_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX = @"lib.org.bouncycastle.jcajce.provider.asymmetric.dh.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricDH, PREFIX, NSString *)

inline id<JavaUtilMap> LibOrgBouncycastleJcajceProviderAsymmetricDH_get_generalDhAttributes(void);
static id<JavaUtilMap> LibOrgBouncycastleJcajceProviderAsymmetricDH_generalDhAttributes;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricDH, generalDhAttributes, id<JavaUtilMap>)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricDH)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDH

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDH_init(self);
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
    { "generalDhAttributes", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 1, 2, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, &LibOrgBouncycastleJcajceProviderAsymmetricDH_generalDhAttributes, "Ljava/util/Map<Ljava/lang/String;Ljava/lang/String;>;", "LLibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDH = { "DH", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, fields, 7, 0x1, 1, 2, -1, 3, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDH;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricDH class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricDH_generalDhAttributes = new_JavaUtilHashMap_init();
    {
      (void) [LibOrgBouncycastleJcajceProviderAsymmetricDH_generalDhAttributes putWithId:@"SupportedKeyClasses" withId:@"javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey"];
      (void) [LibOrgBouncycastleJcajceProviderAsymmetricDH_generalDhAttributes putWithId:@"SupportedKeyFormats" withId:@"PKCS#8|X.509"];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricDH)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDH_init(LibOrgBouncycastleJcajceProviderAsymmetricDH *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDH *new_LibOrgBouncycastleJcajceProviderAsymmetricDH_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDH, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDH *create_LibOrgBouncycastleJcajceProviderAsymmetricDH_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDH, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDH)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"KeyPairGenerator.DH" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyPairGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN" withNSString:@"DH"];
  [provider addAttributesWithNSString:@"KeyAgreement.DH" withJavaUtilMap:JreLoadStatic(LibOrgBouncycastleJcajceProviderAsymmetricDH, generalDhAttributes)];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DH" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyAgreement.DIFFIEHELLMAN" withNSString:@"DH"];
  [provider addAlgorithmWithNSString:@"KeyAgreement" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_alg_ESDH) withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithRFC2631KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement" withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_alg_SSDH) withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithRFC2631KDF")];
  [provider addAlgorithmWithNSString:@"KeyFactory.DH" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.DIFFIEHELLMAN" withNSString:@"DH"];
  [provider addAlgorithmWithNSString:@"AlgorithmParameters.DH" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"AlgorithmParametersSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN" withNSString:@"DH"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN" withNSString:@"DH"];
  [provider addAlgorithmWithNSString:@"AlgorithmParameterGenerator.DH" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"DhAlgorithmParameterGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"Cipher.IES" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IES")];
  [provider addAlgorithmWithNSString:@"Cipher.IESwithAES-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithAESCBC")];
  [provider addAlgorithmWithNSString:@"Cipher.IESWITHAES-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithAESCBC")];
  [provider addAlgorithmWithNSString:@"Cipher.IESWITHDESEDE-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithDESedeCBC")];
  [provider addAlgorithmWithNSString:@"Cipher.DHIES" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IES")];
  [provider addAlgorithmWithNSString:@"Cipher.DHIESwithAES-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithAESCBC")];
  [provider addAlgorithmWithNSString:@"Cipher.DHIESWITHAES-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithAESCBC")];
  [provider addAlgorithmWithNSString:@"Cipher.DHIESWITHDESEDE-CBC" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhIESCipher$IESwithDESedeCBC")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHWITHSHA1KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithSHA1KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHWITHSHA224KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithSHA224KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHWITHSHA256KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithSHA256KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHWITHSHA384KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithSHA384KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHWITHSHA512KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHwithSHA512KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA1KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA1KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA224KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA224KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA256KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA256KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA384KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA384KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA512KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA512KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA1CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA1CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA224CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA224CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA256CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA256CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA384CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA384CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.DHUWITHSHA512CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$DHUwithSHA512CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA1KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA1KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA224KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA224KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA256KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA256KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA384KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA384KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA512KDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA512KDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA1CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA1CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA224CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA224CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA256CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA256CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA384CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA384CKDF")];
  [provider addAlgorithmWithNSString:@"KeyAgreement.MQVWITHSHA512CKDF" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDH_PREFIX, @"JcajceDhKeyAgreementSpi$MQVwithSHA512CKDF")];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement) withNSString:@"DH" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init()];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber) withNSString:@"DH" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricDhJcajceDhKeyFactorySpi_init()];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastleJcajceProviderAsymmetricDH;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDH_Mappings)