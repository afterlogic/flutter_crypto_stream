//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/BouncyCastleProvider.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "AlgorithmProvider.h"
#include "AsymmetricKeyInfoConverter.h"
#include "BouncyCastleProvider.h"
#include "BouncyCastleProviderConfiguration.h"
#include "ClassUtil.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "McElieceCCA2KeyFactorySpi.h"
#include "McElieceKeyFactorySpi.h"
#include "NHKeyFactorySpi.h"
#include "PQCObjectIdentifiers.h"
#include "PrivateKeyInfo.h"
#include "ProviderConfiguration.h"
#include "QTESLAKeyFactorySpi.h"
#include "RainbowKeyFactorySpi.h"
#include "Sphincs256KeyFactorySpi.h"
#include "SubjectPublicKeyInfo.h"
#include "XMSSKeyFactorySpi.h"
#include "XMSSMTKeyFactorySpi.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/InternalError.h"
#include "java/security/AccessController.h"
#include "java/security/PrivateKey.h"
#include "java/security/PrivilegedAction.h"
#include "java/security/Provider.h"
#include "java/security/PublicKey.h"
#include "java/util/HashMap.h"
#include "java/util/Iterator.h"
#include "java/util/Map.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleJceProviderBouncyCastleProvider ()

- (void)setup;

- (void)loadAlgorithmsWithNSString:(NSString *)packageName
                 withNSStringArray:(IOSObjectArray *)names;

- (void)loadPQCKeys;

+ (id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter>)getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)algorithm;

@end

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_info(void);
inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_set_info(NSString *value);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_info = @"BouncyCastle Security Provider v1.61";
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJceProviderBouncyCastleProvider, info, NSString *)

inline id<JavaUtilMap> LibOrgBouncycastleJceProviderBouncyCastleProvider_get_keyInfoConverters(void);
static id<JavaUtilMap> LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, keyInfoConverters, id<JavaUtilMap>)

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SYMMETRIC_PACKAGE(void);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_PACKAGE = @"lib.org.bouncycastle.jcajce.provider.symmetric.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SYMMETRIC_PACKAGE, NSString *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SYMMETRIC_GENERIC(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_GENERIC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SYMMETRIC_GENERIC, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SYMMETRIC_MACS(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_MACS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SYMMETRIC_MACS, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SYMMETRIC_CIPHERS(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_CIPHERS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SYMMETRIC_CIPHERS, IOSObjectArray *)

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_ASYMMETRIC_PACKAGE(void);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_PACKAGE = @"lib.org.bouncycastle.jcajce.provider.asymmetric.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, ASYMMETRIC_PACKAGE, NSString *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_ASYMMETRIC_GENERIC(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_GENERIC;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, ASYMMETRIC_GENERIC, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_ASYMMETRIC_CIPHERS(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_CIPHERS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, ASYMMETRIC_CIPHERS, IOSObjectArray *)

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_DIGEST_PACKAGE(void);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGEST_PACKAGE = @"lib.org.bouncycastle.jcajce.provider.digest.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, DIGEST_PACKAGE, NSString *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_DIGESTS(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGESTS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, DIGESTS, IOSObjectArray *)

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_KEYSTORE_PACKAGE(void);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORE_PACKAGE = @"lib.org.bouncycastle.jcajce.provider.keystore.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, KEYSTORE_PACKAGE, NSString *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_KEYSTORES(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORES;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, KEYSTORES, IOSObjectArray *)

inline NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SECURE_RANDOM_PACKAGE(void);
static NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOM_PACKAGE = @"lib.org.bouncycastle.jcajce.provider.drbg.";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SECURE_RANDOM_PACKAGE, NSString *)

inline IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_get_SECURE_RANDOMS(void);
static IOSObjectArray *LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOMS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderBouncyCastleProvider, SECURE_RANDOMS, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleJceProviderBouncyCastleProvider_setup(LibOrgBouncycastleJceProviderBouncyCastleProvider *self);

__attribute__((unused)) static void LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(LibOrgBouncycastleJceProviderBouncyCastleProvider *self, NSString *packageName, IOSObjectArray *names);

__attribute__((unused)) static void LibOrgBouncycastleJceProviderBouncyCastleProvider_loadPQCKeys(LibOrgBouncycastleJceProviderBouncyCastleProvider *self);

__attribute__((unused)) static id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter> LibOrgBouncycastleJceProviderBouncyCastleProvider_getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm);

@interface LibOrgBouncycastleJceProviderBouncyCastleProvider_1 : NSObject < JavaSecurityPrivilegedAction > {
 @public
  LibOrgBouncycastleJceProviderBouncyCastleProvider *this$0_;
}

- (instancetype)initWithLibOrgBouncycastleJceProviderBouncyCastleProvider:(LibOrgBouncycastleJceProviderBouncyCastleProvider *)outer$;

- (id)run;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderBouncyCastleProvider_1)

__attribute__((unused)) static void LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *self, LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$);

__attribute__((unused)) static LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *new_LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *create_LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJceProviderBouncyCastleProvider)

NSString *LibOrgBouncycastleJceProviderBouncyCastleProvider_PROVIDER_NAME = @"BC";
id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration> LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION;

@implementation LibOrgBouncycastleJceProviderBouncyCastleProvider

+ (NSString *)PROVIDER_NAME {
  return LibOrgBouncycastleJceProviderBouncyCastleProvider_PROVIDER_NAME;
}

+ (id<LibOrgBouncycastleJcajceProviderConfigProviderConfiguration>)CONFIGURATION {
  return LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)setup {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_setup(self);
}

- (void)loadAlgorithmsWithNSString:(NSString *)packageName
                 withNSStringArray:(IOSObjectArray *)names {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, packageName, names);
}

- (void)loadPQCKeys {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadPQCKeys(self);
}

- (void)setParameterWithNSString:(NSString *)parameterName
                          withId:(id)parameter {
  @synchronized(LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION) {
    [((LibOrgBouncycastleJceProviderBouncyCastleProviderConfiguration *) nil_chk(((LibOrgBouncycastleJceProviderBouncyCastleProviderConfiguration *) cast_chk(LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION, [LibOrgBouncycastleJceProviderBouncyCastleProviderConfiguration class])))) setParameterWithNSString:parameterName withId:parameter];
  }
}

- (jboolean)hasAlgorithmWithNSString:(NSString *)type
                        withNSString:(NSString *)name {
  return [self containsKeyWithId:JreStrcat("$C$", type, '.', name)] || [self containsKeyWithId:JreStrcat("$$C$", @"Alg.Alias.", type, '.', name)];
}

- (void)addAlgorithmWithNSString:(NSString *)key
                    withNSString:(NSString *)value {
  if ([self containsKeyWithId:key]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$$", @"duplicate provider key (", key, @") found"));
  }
  (void) [self putWithId:key withId:value];
}

- (void)addAlgorithmWithNSString:(NSString *)type
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                    withNSString:(NSString *)className_ {
  [self addAlgorithmWithNSString:JreStrcat("$C@", type, '.', oid) withNSString:className_];
  [self addAlgorithmWithNSString:JreStrcat("$$@", type, @".OID.", oid) withNSString:className_];
}

- (void)addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
       withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:(id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter>)keyInfoConverter {
  @synchronized(LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters) {
    (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters)) putWithId:oid withId:keyInfoConverter];
  }
}

- (void)addAttributesWithNSString:(NSString *)key
                  withJavaUtilMap:(id<JavaUtilMap>)attributeMap {
  for (id<JavaUtilIterator> it = [((id<JavaUtilSet>) nil_chk([((id<JavaUtilMap>) nil_chk(attributeMap)) keySet])) iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    NSString *attributeName = (NSString *) cast_chk([it next], [NSString class]);
    NSString *attributeKey = JreStrcat("$C$", key, ' ', attributeName);
    if ([self containsKeyWithId:attributeKey]) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$$", @"duplicate provider attribute key (", attributeKey, @") found"));
    }
    (void) [self putWithId:attributeKey withId:[attributeMap getWithId:attributeName]];
  }
}

+ (id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter>)getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)algorithm {
  return LibOrgBouncycastleJceProviderBouncyCastleProvider_getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(algorithm);
}

+ (id<JavaSecurityPublicKey>)getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)publicKeyInfo {
  return LibOrgBouncycastleJceProviderBouncyCastleProvider_getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(publicKeyInfo);
}

+ (id<JavaSecurityPrivateKey>)getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)privateKeyInfo {
  return LibOrgBouncycastleJceProviderBouncyCastleProvider_getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(privateKeyInfo);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 11, -1, 12, -1, -1 },
    { NULL, "LLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter;", 0xa, 13, 14, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x9, 15, 16, 17, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x9, 18, 19, 17, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(setup);
  methods[2].selector = @selector(loadAlgorithmsWithNSString:withNSStringArray:);
  methods[3].selector = @selector(loadPQCKeys);
  methods[4].selector = @selector(setParameterWithNSString:withId:);
  methods[5].selector = @selector(hasAlgorithmWithNSString:withNSString:);
  methods[6].selector = @selector(addAlgorithmWithNSString:withNSString:);
  methods[7].selector = @selector(addAlgorithmWithNSString:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  methods[8].selector = @selector(addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:);
  methods[9].selector = @selector(addAttributesWithNSString:withJavaUtilMap:);
  methods[10].selector = @selector(getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[11].selector = @selector(getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[12].selector = @selector(getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "info", "LNSString;", .constantValue.asLong = 0, 0xa, -1, 20, -1, -1 },
    { "PROVIDER_NAME", "LNSString;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "CONFIGURATION", "LLibOrgBouncycastleJcajceProviderConfigProviderConfiguration;", .constantValue.asLong = 0, 0x19, -1, 22, -1, -1 },
    { "keyInfoConverters", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "SYMMETRIC_PACKAGE", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 24, -1, -1 },
    { "SYMMETRIC_GENERIC", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 25, -1, -1 },
    { "SYMMETRIC_MACS", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 26, -1, -1 },
    { "SYMMETRIC_CIPHERS", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 27, -1, -1 },
    { "ASYMMETRIC_PACKAGE", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 28, -1, -1 },
    { "ASYMMETRIC_GENERIC", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 29, -1, -1 },
    { "ASYMMETRIC_CIPHERS", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 30, -1, -1 },
    { "DIGEST_PACKAGE", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 31, -1, -1 },
    { "DIGESTS", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 32, -1, -1 },
    { "KEYSTORE_PACKAGE", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 33, -1, -1 },
    { "KEYSTORES", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 34, -1, -1 },
    { "SECURE_RANDOM_PACKAGE", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 35, -1, -1 },
    { "SECURE_RANDOMS", "[LNSString;", .constantValue.asLong = 0, 0x1a, -1, 36, -1, -1 },
  };
  static const void *ptrTable[] = { "loadAlgorithms", "LNSString;[LNSString;", "setParameter", "LNSString;LNSObject;", "hasAlgorithm", "LNSString;LNSString;", "addAlgorithm", "LNSString;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;", "addKeyInfoConverter", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter;", "addAttributes", "LNSString;LJavaUtilMap;", "(Ljava/lang/String;Ljava/util/Map<Ljava/lang/String;Ljava/lang/String;>;)V", "getAsymmetricKeyInfoConverter", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "getPublicKey", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "LJavaIoIOException;", "getPrivateKey", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", &LibOrgBouncycastleJceProviderBouncyCastleProvider_info, &LibOrgBouncycastleJceProviderBouncyCastleProvider_PROVIDER_NAME, &LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION, &LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_PACKAGE, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_GENERIC, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_MACS, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_CIPHERS, &LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_PACKAGE, &LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_GENERIC, &LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_CIPHERS, &LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGEST_PACKAGE, &LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGESTS, &LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORE_PACKAGE, &LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORES, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOM_PACKAGE, &LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOMS };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderBouncyCastleProvider = { "BouncyCastleProvider", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x11, 13, 17, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderBouncyCastleProvider;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJceProviderBouncyCastleProvider class]) {
    LibOrgBouncycastleJceProviderBouncyCastleProvider_CONFIGURATION = new_LibOrgBouncycastleJceProviderBouncyCastleProviderConfiguration_init();
    LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters = new_JavaUtilHashMap_init();
    LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_GENERIC = [IOSObjectArray newArrayWithObjects:(id[]){ @"PBEPBKDF1", @"PBEPBKDF2", @"PBEPKCS12", @"TLSKDF", @"JcajceSCRYPT" } count:5 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_MACS = [IOSObjectArray newArrayWithObjects:(id[]){ @"JcajceSipHash", @"JcajcePoly1305" } count:2 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_CIPHERS = [IOSObjectArray newArrayWithObjects:(id[]){ @"AES", @"ARC4", @"ARIA", @"Blowfish", @"Camellia", @"CAST5", @"CAST6", @"ChaCha", @"DES", @"DESede", @"GOST28147", @"Grainv1", @"Grain128", @"HC128", @"HC256", @"IDEA", @"Noekeon", @"RC2", @"RC5", @"RC6", @"Rijndael", @"Salsa20", @"JcajceSEED", @"Serpent", @"Shacal2", @"Skipjack", @"SM4", @"TEA", @"Twofish", @"Threefish", @"VMPC", @"VMPCKSA3", @"XTEA", @"XSalsa20", @"OpenSSLPBKDF", @"DSTU7624", @"GOST3412_2015" } count:37 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_GENERIC = [IOSObjectArray newArrayWithObjects:(id[]){ @"X509", @"IES" } count:2 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_CIPHERS = [IOSObjectArray newArrayWithObjects:(id[]){ @"JcajceDSA", @"DH", @"EC", @"RSA", @"GOST", @"ECGOST", @"ElGamal", @"DSTU4145", @"GM", @"EdEC" } count:10 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGESTS = [IOSObjectArray newArrayWithObjects:(id[]){ @"GOST3411", @"Keccak", @"MD2", @"MD4", @"MD5", @"SHA1", @"RIPEMD128", @"RIPEMD160", @"RIPEMD256", @"RIPEMD320", @"SHA224", @"SHA256", @"SHA384", @"SHA512", @"SHA3", @"Skein", @"SM3", @"Tiger", @"Whirlpool", @"Blake2b", @"Blake2s", @"DSTU7564" } count:22 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORES = [IOSObjectArray newArrayWithObjects:(id[]){ @"BC", @"BCFKS", @"PKCS12" } count:3 type:NSString_class_()];
    LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOMS = [IOSObjectArray newArrayWithObjects:(id[]){ @"DRBG" } count:1 type:NSString_class_()];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJceProviderBouncyCastleProvider)
  }
}

@end

void LibOrgBouncycastleJceProviderBouncyCastleProvider_init(LibOrgBouncycastleJceProviderBouncyCastleProvider *self) {
  JavaSecurityProvider_initWithNSString_withDouble_withNSString_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_PROVIDER_NAME, 1.61, LibOrgBouncycastleJceProviderBouncyCastleProvider_info);
  (void) JavaSecurityAccessController_doPrivilegedWithJavaSecurityPrivilegedAction_(new_LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(self));
}

LibOrgBouncycastleJceProviderBouncyCastleProvider *new_LibOrgBouncycastleJceProviderBouncyCastleProvider_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderBouncyCastleProvider, init)
}

LibOrgBouncycastleJceProviderBouncyCastleProvider *create_LibOrgBouncycastleJceProviderBouncyCastleProvider_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderBouncyCastleProvider, init)
}

void LibOrgBouncycastleJceProviderBouncyCastleProvider_setup(LibOrgBouncycastleJceProviderBouncyCastleProvider *self) {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGEST_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_DIGESTS);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_GENERIC);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_MACS);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_SYMMETRIC_CIPHERS);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_GENERIC);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_ASYMMETRIC_CIPHERS);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORE_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_KEYSTORES);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(self, LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOM_PACKAGE, LibOrgBouncycastleJceProviderBouncyCastleProvider_SECURE_RANDOMS);
  LibOrgBouncycastleJceProviderBouncyCastleProvider_loadPQCKeys(self);
  (void) [self putWithId:@"X509Store.CERTIFICATE/COLLECTION" withId:@"lib.org.bouncycastle.jce.provider.X509StoreCertCollection"];
  (void) [self putWithId:@"X509Store.ATTRIBUTECERTIFICATE/COLLECTION" withId:@"lib.org.bouncycastle.jce.provider.X509StoreAttrCertCollection"];
  (void) [self putWithId:@"X509Store.CRL/COLLECTION" withId:@"lib.org.bouncycastle.jce.provider.X509StoreCRLCollection"];
  (void) [self putWithId:@"X509Store.CERTIFICATEPAIR/COLLECTION" withId:@"lib.org.bouncycastle.jce.provider.X509StoreCertPairCollection"];
  (void) [self putWithId:@"X509StreamParser.CERTIFICATE" withId:@"lib.org.bouncycastle.jce.provider.X509CertParser"];
  (void) [self putWithId:@"X509StreamParser.ATTRIBUTECERTIFICATE" withId:@"lib.org.bouncycastle.jce.provider.X509AttrCertParser"];
  (void) [self putWithId:@"X509StreamParser.CRL" withId:@"lib.org.bouncycastle.jce.provider.X509CRLParser"];
  (void) [self putWithId:@"X509StreamParser.CERTIFICATEPAIR" withId:@"lib.org.bouncycastle.jce.provider.X509CertPairParser"];
  (void) [self putWithId:@"Cipher.BROKENPBEWITHMD5ANDDES" withId:@"lib.org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES"];
  (void) [self putWithId:@"Cipher.BROKENPBEWITHSHA1ANDDES" withId:@"lib.org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES"];
  (void) [self putWithId:@"Cipher.OLDPBEWITHSHAANDTWOFISH-CBC" withId:@"lib.org.bouncycastle.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish"];
  (void) [self putWithId:@"CertPathValidator.RFC3281" withId:@"lib.org.bouncycastle.jce.provider.PKIXAttrCertPathValidatorSpi"];
  (void) [self putWithId:@"CertPathBuilder.RFC3281" withId:@"lib.org.bouncycastle.jce.provider.PKIXAttrCertPathBuilderSpi"];
  (void) [self putWithId:@"CertPathValidator.RFC3280" withId:@"lib.org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi"];
  (void) [self putWithId:@"CertPathBuilder.RFC3280" withId:@"lib.org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi"];
  (void) [self putWithId:@"CertPathValidator.PKIX" withId:@"lib.org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi"];
  (void) [self putWithId:@"CertPathBuilder.PKIX" withId:@"lib.org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi"];
  (void) [self putWithId:@"CertStore.Collection" withId:@"lib.org.bouncycastle.jce.provider.CertStoreCollectionSpi"];
  (void) [self putWithId:@"CertStore.Multi" withId:@"lib.org.bouncycastle.jce.provider.MultiCertStoreSpi"];
}

void LibOrgBouncycastleJceProviderBouncyCastleProvider_loadAlgorithmsWithNSString_withNSStringArray_(LibOrgBouncycastleJceProviderBouncyCastleProvider *self, NSString *packageName, IOSObjectArray *names) {
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(names))->size_; i++) {
    IOSClass *clazz = LibOrgBouncycastleJcajceProviderSymmetricUtilClassUtil_loadClassWithIOSClass_withNSString_(LibOrgBouncycastleJceProviderBouncyCastleProvider_class_(), JreStrcat("$$$", packageName, IOSObjectArray_Get(names, i), @"$Mappings"));
    if (clazz != nil) {
      @try {
        [((LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider *) nil_chk(((LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider *) cast_chk([clazz newInstance], [LibOrgBouncycastleJcajceProviderUtilAlgorithmProvider class])))) configureWithLibOrgBouncycastleJcajceProviderConfigConfigurableProvider:self];
      }
      @catch (JavaLangException *e) {
        @throw new_JavaLangInternalError_initWithNSString_(JreStrcat("$$$$@", @"cannot create instance of ", packageName, IOSObjectArray_Get(names, i), @"$Mappings : ", e));
      }
    }
  }
}

void LibOrgBouncycastleJceProviderBouncyCastleProvider_loadPQCKeys(LibOrgBouncycastleJceProviderBouncyCastleProvider *self) {
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, sphincs256) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, newHope) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderNewhopeNHKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderXmssXMSSKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss_mt) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderXmssXMSSMTKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, mcEliece) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, mcElieceCca2) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, rainbow) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, qTESLA_I) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, qTESLA_III_size) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, qTESLA_III_speed) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, qTESLA_p_I) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init()];
  [self addKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, qTESLA_p_III) withLibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter:new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init()];
}

id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter> LibOrgBouncycastleJceProviderBouncyCastleProvider_getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm) {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_initialize();
  @synchronized(LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters) {
    return (id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter>) cast_check([((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJceProviderBouncyCastleProvider_keyInfoConverters)) getWithId:algorithm], LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter_class_());
  }
}

id<JavaSecurityPublicKey> LibOrgBouncycastleJceProviderBouncyCastleProvider_getPublicKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *publicKeyInfo) {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_initialize();
  id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter> converter = LibOrgBouncycastleJceProviderBouncyCastleProvider_getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(publicKeyInfo)) getAlgorithm])) getAlgorithm]);
  if (converter == nil) {
    return nil;
  }
  return [converter generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:publicKeyInfo];
}

id<JavaSecurityPrivateKey> LibOrgBouncycastleJceProviderBouncyCastleProvider_getPrivateKeyWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *privateKeyInfo) {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_initialize();
  id<LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter> converter = LibOrgBouncycastleJceProviderBouncyCastleProvider_getAsymmetricKeyInfoConverterWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(privateKeyInfo)) getPrivateKeyAlgorithm])) getAlgorithm]);
  if (converter == nil) {
    return nil;
  }
  return [converter generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:privateKeyInfo];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderBouncyCastleProvider)

@implementation LibOrgBouncycastleJceProviderBouncyCastleProvider_1

- (instancetype)initWithLibOrgBouncycastleJceProviderBouncyCastleProvider:(LibOrgBouncycastleJceProviderBouncyCastleProvider *)outer$ {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(self, outer$);
  return self;
}

- (id)run {
  LibOrgBouncycastleJceProviderBouncyCastleProvider_setup(this$0_);
  return nil;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleJceProviderBouncyCastleProvider:);
  methods[1].selector = @selector(run);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleJceProviderBouncyCastleProvider;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleJceProviderBouncyCastleProvider;", "init" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderBouncyCastleProvider_1 = { "", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x8010, 2, 1, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderBouncyCastleProvider_1;
}

@end

void LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *self, LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *new_LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderBouncyCastleProvider_1, initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_, outer$)
}

LibOrgBouncycastleJceProviderBouncyCastleProvider_1 *create_LibOrgBouncycastleJceProviderBouncyCastleProvider_1_initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_(LibOrgBouncycastleJceProviderBouncyCastleProvider *outer$) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderBouncyCastleProvider_1, initWithLibOrgBouncycastleJceProviderBouncyCastleProvider_, outer$)
}
