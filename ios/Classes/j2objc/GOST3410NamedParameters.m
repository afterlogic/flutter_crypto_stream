//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptopro/GOST3410NamedParameters.java
//

#include "ASN1ObjectIdentifier.h"
#include "CryptoProObjectIdentifiers.h"
#include "GOST3410NamedParameters.h"
#include "GOST3410ParamSetParameters.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"

inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_get_cryptoProA(void);
inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_set_cryptoProA(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *value);
static LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProA;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters, cryptoProA, LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)

inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_get_cryptoProB(void);
inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_set_cryptoProB(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *value);
static LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProB;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters, cryptoProB, LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)

inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_get_cryptoProXchA(void);
inline LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_set_cryptoProXchA(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *value);
static LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProXchA;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters, cryptoProXchA, LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters)

JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds;
JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params;
JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_names;

@implementation LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters

+ (JavaUtilHashtable *)objIds {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds;
}

+ (JavaUtilHashtable *)params {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(oid);
}

+ (id<JavaUtilEnumeration>)getNames {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getNames();
}

+ (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)getByNameWithNSString:(NSString *)name {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getByNameWithNSString_(name);
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name {
  return LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getOIDWithNSString_(name);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x9, 4, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(getNames);
  methods[3].selector = @selector(getByNameWithNSString:);
  methods[4].selector = @selector(getOIDWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "objIds", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 5, -1, -1 },
    { "params", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 6, -1, -1 },
    { "names", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 7, -1, -1 },
    { "cryptoProA", "LLibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters;", .constantValue.asLong = 0, 0xa, -1, 8, -1, -1 },
    { "cryptoProB", "LLibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters;", .constantValue.asLong = 0, 0xa, -1, 9, -1, -1 },
    { "cryptoProXchA", "LLibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters;", .constantValue.asLong = 0, 0xa, -1, 10, -1, -1 },
  };
  static const void *ptrTable[] = { "getByOID", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "getByName", "LNSString;", "getOID", &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds, &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params, &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_names, &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProA, &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProB, &LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProXchA };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters = { "GOST3410NamedParameters", "lib.org.bouncycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 5, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters class]) {
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds = new_JavaUtilHashtable_init();
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params = new_JavaUtilHashtable_init();
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_names = new_JavaUtilHashtable_init();
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProA = new_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(1024, new_JavaMathBigInteger_initWithNSString_(@"127021248288932417465907042777176443525787653508916535812817507265705031260985098497423188333483401180925999995120988934130659205614996724254121049274349357074920312769561451689224110579311248812610229678534638401693520013288995000362260684222750813532307004517341633685004541062586971416883686778842537820383"), new_JavaMathBigInteger_initWithNSString_(@"68363196144955700784444165611827252895102170888761442055095051287550314083023"), new_JavaMathBigInteger_initWithNSString_(@"100997906755055304772081815535925224869841082572053457874823515875577147990529272777244152852699298796483356699682842027972896052747173175480590485607134746852141928680912561502802222185647539190902656116367847270145019066794290930185446216399730872221732889830323194097355403213400972588322876850946740663962"));
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProB = new_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(1024, new_JavaMathBigInteger_initWithNSString_(@"139454871199115825601409655107690713107041707059928031797758001454375765357722984094124368522288239833039114681648076688236921220737322672160740747771700911134550432053804647694904686120113087816240740184800477047157336662926249423571248823968542221753660143391485680840520336859458494803187341288580489525163"), new_JavaMathBigInteger_initWithNSString_(@"79885141663410976897627118935756323747307951916507639758300472692338873533959"), new_JavaMathBigInteger_initWithNSString_(@"42941826148615804143873447737955502392672345968607143066798112994089471231420027060385216699563848719957657284814898909770759462613437669456364882730370838934791080835932647976778601915343474400961034231316672578686920482194932878633360203384797092684342247621055760235016132614780652761028509445403338652341"));
    LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProXchA = new_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(1024, new_JavaMathBigInteger_initWithNSString_(@"142011741597563481196368286022318089743276138395243738762872573441927459393512718973631166078467600360848946623567625795282774719212241929071046134208380636394084512691828894000571524625445295769349356752728956831541775441763139384457191755096847107846595662547942312293338483924514339614727760681880609734239"), new_JavaMathBigInteger_initWithNSString_(@"91771529896554605945588149018382750217296858393520724172743325725474374979801"), new_JavaMathBigInteger_initWithNSString_(@"133531813272720673433859519948319001217942375967847486899482359599369642528734712461590403327731821410328012529253871914788598993103310567744136196364803064721377826656898686468463277710150809401182608770201615324990468332931294920912776241137878030224355746606283971659376426832674269780880061631528163475887"));
    {
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_A) withId:LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProA];
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_B) withId:LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProB];
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_XchA) withId:LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_cryptoProXchA];
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds putWithId:@"GostR3410-94-CryptoPro-A" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_A)];
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds putWithId:@"GostR3410-94-CryptoPro-B" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_B)];
      (void) [LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds putWithId:@"GostR3410-94-CryptoPro-XchA" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_94_CryptoPro_XchA)];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters)
  }
}

@end

void LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_init(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters *self) {
  NSObject_init(self);
}

LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters *new_LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters, init)
}

LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters *create_LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters, init)
}

LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_initialize();
  return (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params)) getWithId:oid], [LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters class]);
}

id<JavaUtilEnumeration> LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getNames() {
  LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_initialize();
  return [((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds)) keys];
}

LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getByNameWithNSString_(NSString *name) {
  LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_initialize();
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds)) getWithId:name], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  if (oid != nil) {
    return (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_params)) getWithId:oid], [LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters class]);
  }
  return nil;
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_getOIDWithNSString_(NSString *name) {
  LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_initialize();
  return (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters_objIds)) getWithId:name], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CryptoproGOST3410NamedParameters)
