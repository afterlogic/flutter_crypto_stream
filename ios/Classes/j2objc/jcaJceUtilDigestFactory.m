//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/util/jcaJceUtilDigestFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "Digest.h"
#include "DigestFactory.h"
#include "J2ObjC_source.h"
#include "NISTObjectIdentifiers.h"
#include "OIWObjectIdentifiers.h"
#include "PKCSObjectIdentifiers.h"
#include "Strings.h"
#include "java/util/HashMap.h"
#include "java/util/HashSet.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "jcaJceUtilDigestFactory.h"

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_md5(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_md5(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, md5, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha1(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha1(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha1, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha224(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha224(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha224, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha256(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha256(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha256, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha384(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha384(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha384, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha512(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha512(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha512, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha512_224(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha512_224(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha512_224, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha512_256(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha512_256(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha512_256, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha3_224(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha3_224(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha3_224, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha3_256(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha3_256(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha3_256, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha3_384(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha3_384(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha3_384, id<JavaUtilSet>)

inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_sha3_512(void);
inline id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_sha3_512(id<JavaUtilSet> value);
static id<JavaUtilSet> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, sha3_512, id<JavaUtilSet>)

inline id<JavaUtilMap> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_get_oids(void);
inline id<JavaUtilMap> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_set_oids(id<JavaUtilMap> value);
static id<JavaUtilMap> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, oids, id<JavaUtilMap>)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory)

@implementation LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<LibOrgBouncycastleCryptoDigest>)getDigestWithNSString:(NSString *)digestName {
  return LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getDigestWithNSString_(digestName);
}

+ (jboolean)isSameDigestWithNSString:(NSString *)digest1
                        withNSString:(NSString *)digest2 {
  return LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_isSameDigestWithNSString_withNSString_(digest1, digest2);
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)digestName {
  return LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_(digestName);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x9, 4, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getDigestWithNSString:);
  methods[2].selector = @selector(isSameDigestWithNSString:withNSString:);
  methods[3].selector = @selector(getOIDWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "md5", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 5, -1, -1 },
    { "sha1", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 6, -1, -1 },
    { "sha224", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
    { "sha256", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 8, -1, -1 },
    { "sha384", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 9, -1, -1 },
    { "sha512", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 10, -1, -1 },
    { "sha512_224", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 11, -1, -1 },
    { "sha512_256", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 12, -1, -1 },
    { "sha3_224", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 13, -1, -1 },
    { "sha3_256", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 14, -1, -1 },
    { "sha3_384", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 15, -1, -1 },
    { "sha3_512", "LJavaUtilSet;", .constantValue.asLong = 0, 0xa, -1, 16, -1, -1 },
    { "oids", "LJavaUtilMap;", .constantValue.asLong = 0, 0xa, -1, 17, -1, -1 },
  };
  static const void *ptrTable[] = { "getDigest", "LNSString;", "isSameDigest", "LNSString;LNSString;", "getOID", &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512, &LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory = { "jcaJceUtilDigestFactory", "lib.org.bouncycastle.jcajce.provider.util", ptrTable, methods, fields, 7, 0x1, 4, 13, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory class]) {
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512 = new_JavaUtilHashSet_init();
    LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids = new_JavaUtilHashMap_init();
    {
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5)) addWithId:@"MD5"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, md5))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) addWithId:@"SHA1"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) addWithId:@"SHA-1"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) addWithId:@"SHA224"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) addWithId:@"SHA-224"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) addWithId:@"SHA256"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) addWithId:@"SHA-256"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) addWithId:@"SHA384"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) addWithId:@"SHA-384"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) addWithId:@"SHA512"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) addWithId:@"SHA-512"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) addWithId:@"SHA512(224)"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) addWithId:@"SHA-512(224)"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_224))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) addWithId:@"SHA512(256)"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) addWithId:@"SHA-512(256)"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224)) addWithId:@"SHA3-224"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_224))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256)) addWithId:@"SHA3-256"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384)) addWithId:@"SHA3-384"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_384))) getId]];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512)) addWithId:@"SHA3-512"];
      [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512)) addWithId:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_512))) getId]];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"MD5" withId:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, md5)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, md5) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, md5)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA1" withId:JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-1" withId:JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA224" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-224" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA256" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-256" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA384" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-384" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA512" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-512" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA512(224)" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-512(224)" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_224) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA512(256)" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA-512(256)" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512_256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA3-224" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_224) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_224)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA3-256" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_256)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA3-384" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_384)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_384) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_384)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:@"SHA3-512" withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_512)];
      (void) [((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) putWithId:[JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_512) getId] withId:JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha3_512)];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory)
  }
}

@end

void LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *new_LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, init)
}

LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory *create_LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, init)
}

id<LibOrgBouncycastleCryptoDigest> LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getDigestWithNSString_(NSString *digestName) {
  LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_initialize();
  digestName = LibOrgBouncycastleUtilStrings_toUpperCaseWithNSString_(digestName);
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA1();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createMD5();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA224();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA256();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA384();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512_224();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA512_256();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA3_224();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA3_256();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA3_384();
  }
  if ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512)) containsWithId:digestName]) {
    return LibOrgBouncycastleCryptoUtilDigestFactory_createSHA3_512();
  }
  return nil;
}

jboolean LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_isSameDigestWithNSString_withNSString_(NSString *digest1, NSString *digest2) {
  LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_initialize();
  return ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha1)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha224)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha256)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha384)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_224)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha512_256)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_224)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_256)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_384)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_sha3_512)) containsWithId:digest2]) || ([((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5)) containsWithId:digest1] && [((id<JavaUtilSet>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_md5)) containsWithId:digest2]);
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_(NSString *digestName) {
  LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_initialize();
  return (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((id<JavaUtilMap>) nil_chk(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_oids)) getWithId:digestName], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory)

J2OBJC_NAME_MAPPING(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory, "lib.org.bouncycastle.jcajce.provider.util", "LibOrgBouncycastleJcajceProviderUtil")
