//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/DSTU4145.java
//

#include "ASN1ObjectIdentifier.h"
#include "AsymmetricAlgorithmProvider.h"
#include "ConfigurableProvider.h"
#include "DSTU4145.h"
#include "J2ObjC_source.h"
#include "JcajceDstuKeyFactorySpi.h"
#include "UAObjectIdentifiers.h"

inline NSString *LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_get_PREFIX(void);
static NSString *LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX = @"lib.org.bouncycastle.jcajce.provider.asymmetric.dstu.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145, PREFIX, NSString *)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_init(self);
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
  static const void *ptrTable[] = { &LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, "LLibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145 = { "DSTU4145", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, fields, 7, 0x1, 1, 1, -1, 1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_init(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145 *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145 *new_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145 *create_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:(id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>)provider {
  [((id<LibOrgBouncycastleJcajceProviderConfigConfigurableProvider>) nil_chk(provider)) addAlgorithmWithNSString:@"KeyFactory.DSTU4145" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, @"JcajceDstuKeyFactorySpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.DSTU-4145-2002" withNSString:@"DSTU4145"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyFactory.DSTU4145-3410" withNSString:@"DSTU4145"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145le) withNSString:@"DSTU4145" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyFactorySpi_init()];
  [self registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145le) withNSString:@"DSTU4145"];
  [self registerOidWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145be) withNSString:@"DSTU4145" withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuKeyFactorySpi_init()];
  [self registerOidAlgorithmParametersWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145be) withNSString:@"DSTU4145"];
  [provider addAlgorithmWithNSString:@"KeyPairGenerator.DSTU4145" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, @"JcajceDstuKeyPairGeneratorSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.DSTU-4145" withNSString:@"DSTU4145"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.KeyPairGenerator.DSTU-4145-2002" withNSString:@"DSTU4145"];
  [provider addAlgorithmWithNSString:@"Signature.DSTU4145" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, @"JcajceDstuSignatureSpi")];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.DSTU-4145" withNSString:@"DSTU4145"];
  [provider addAlgorithmWithNSString:@"Alg.Alias.Signature.DSTU-4145-2002" withNSString:@"DSTU4145"];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"GOST3411" withNSString:@"DSTU4145LE" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, @"SignatureSpiLe") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145le)];
  [self addSignatureAlgorithmWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:provider withNSString:@"GOST3411" withNSString:@"DSTU4145" withNSString:JreStrcat("$$", LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_PREFIX, @"JcajceDstuSignatureSpi") withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastleAsn1UaUAObjectIdentifiers, dstu4145be)];
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
  static const void *ptrTable[] = { "configure", "LLibOrgBouncycastleJcajceProviderConfigConfigurableProvider;", "LLibOrgBouncycastleJcajceProviderAsymmetricDSTU4145;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings = { "Mappings", "lib.org.bouncycastle.jcajce.provider.asymmetric", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings_init(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings *self) {
  LibOrgBouncycastleJcajceProviderUtilAsymmetricAlgorithmProvider_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings *new_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings *create_LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDSTU4145_Mappings)
