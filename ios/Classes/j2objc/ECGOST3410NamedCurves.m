//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptopro/ECGOST3410NamedCurves.java
//

#include "ASN1ObjectIdentifier.h"
#include "CryptoProObjectIdentifiers.h"
#include "ECConstants.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECGOST3410NamedCurves.h"
#include "ECPoint.h"
#include "J2ObjC_source.h"
#include "RosstandartObjectIdentifiers.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves)

JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds;
JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params;
JavaUtilHashtable *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names;

@implementation LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves

+ (JavaUtilHashtable *)objIds {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds;
}

+ (JavaUtilHashtable *)params {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleCryptoParamsECDomainParameters *)getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(oid);
}

+ (id<JavaUtilEnumeration>)getNames {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNames();
}

+ (LibOrgBouncycastleCryptoParamsECDomainParameters *)getByNameWithNSString:(NSString *)name {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByNameWithNSString_(name);
}

+ (NSString *)getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(oid);
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOIDWithNSString:(NSString *)name {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getOIDWithNSString_(name);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsECDomainParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsECDomainParameters;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 4, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x9, 5, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(getNames);
  methods[3].selector = @selector(getByNameWithNSString:);
  methods[4].selector = @selector(getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[5].selector = @selector(getOIDWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "objIds", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 6, -1, -1 },
    { "params", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 7, -1, -1 },
    { "names", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x18, -1, 8, -1, -1 },
  };
  static const void *ptrTable[] = { "getByOID", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "getByName", "LNSString;", "getName", "getOID", &LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds, &LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params, &LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves = { "ECGOST3410NamedCurves", "lib.org.bouncycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves class]) {
    LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds = new_JavaUtilHashtable_init();
    LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params = new_JavaUtilHashtable_init();
    LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names = new_JavaUtilHashtable_init();
    {
      JavaMathBigInteger *mod_p = new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853269984665640564039457584007913129639319");
      JavaMathBigInteger *mod_q = new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853073762908499243225378155805079068850323");
      LibOrgBouncycastleMathEcECCurve_Fp *curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853269984665640564039457584007913129639316"), new_JavaMathBigInteger_initWithNSString_(@"166"), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      LibOrgBouncycastleCryptoParamsECDomainParameters *ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"1") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"64033881142927202683649881450433473985931760268884941288852745803908878638612")], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_A) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853269984665640564039457584007913129639319");
      mod_q = new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853073762908499243225378155805079068850323");
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_(@"115792089237316195423570985008687907853269984665640564039457584007913129639316"), new_JavaMathBigInteger_initWithNSString_(@"166"), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"1") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"64033881142927202683649881450433473985931760268884941288852745803908878638612")], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchA) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_(@"57896044618658097711785492504343953926634992332820282019728792003956564823193");
      mod_q = new_JavaMathBigInteger_initWithNSString_(@"57896044618658097711785492504343953927102133160255826820068844496087732066703");
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_(@"57896044618658097711785492504343953926634992332820282019728792003956564823190"), new_JavaMathBigInteger_initWithNSString_(@"28091019353058090096996979000309560759124368558014865957655842872397301267595"), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"1") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"28792665814854611296992347458380284135028636778229113005756334730996303888124")], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_B) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437841079516630045180471284346843705633502619");
      mod_q = new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437840920882647164081035322601458352298396601");
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437841079516630045180471284346843705633502616"), new_JavaMathBigInteger_initWithNSString_(@"32858"), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"0") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"29818893917731240733471273240314769927240550812383695689146495261604565990247")], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchB) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437841079516630045180471284346843705633502619");
      mod_q = new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437840920882647164081035322601458352298396601");
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_(@"70390085352083305199547718019018437841079516630045180471284346843705633502616"), new_JavaMathBigInteger_initWithNSString_(@"32858"), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"0") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"29818893917731240733471273240314769927240550812383695689146495261604565990247")], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_C) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_withInt_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);
      mod_q = new_JavaMathBigInteger_initWithNSString_withInt_(@"400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67", 16);
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_withInt_(@"C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335", 16), new_JavaMathBigInteger_initWithNSString_withInt_(@"295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513", 16), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, FOUR));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28", 16) withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C", 16)], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, FOUR));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256_paramSetA) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_withInt_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16);
      mod_q = new_JavaMathBigInteger_initWithNSString_withInt_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16);
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_withInt_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4", 16), new_JavaMathBigInteger_initWithNSString_withInt_(@"E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16)], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetA) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_withInt_(@"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F", 16);
      mod_q = new_JavaMathBigInteger_initWithNSString_withInt_(@"800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD", 16);
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_withInt_(@"8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C", 16), new_JavaMathBigInteger_initWithNSString_withInt_(@"687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116", 16), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_(@"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002") withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD", 16)], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetB) withId:ecParams];
      mod_p = new_JavaMathBigInteger_initWithNSString_withInt_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16);
      mod_q = new_JavaMathBigInteger_initWithNSString_withInt_(@"3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED", 16);
      curve = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(mod_p, new_JavaMathBigInteger_initWithNSString_withInt_(@"DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3", 16), new_JavaMathBigInteger_initWithNSString_withInt_(@"B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1", 16), mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, FOUR));
      ecParams = new_LibOrgBouncycastleCryptoParamsECDomainParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curve, [curve createPointWithJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148", 16) withJavaMathBigInteger:new_JavaMathBigInteger_initWithNSString_withInt_(@"F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F", 16)], mod_q, JreLoadStatic(LibOrgBouncycastleMathEcECConstants, FOUR));
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetC) withId:ecParams];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"GostR3410-2001-CryptoPro-A" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_A)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"GostR3410-2001-CryptoPro-B" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_B)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"GostR3410-2001-CryptoPro-C" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_C)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"GostR3410-2001-CryptoPro-XchA" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchA)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"GostR3410-2001-CryptoPro-XchB" withId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchB)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"Tc26-Gost-3410-12-256-paramSetA" withId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256_paramSetA)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"Tc26-Gost-3410-12-512-paramSetA" withId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetA)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"Tc26-Gost-3410-12-512-paramSetB" withId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetB)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds putWithId:@"Tc26-Gost-3410-12-512-paramSetC" withId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetC)];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_A) withId:@"GostR3410-2001-CryptoPro-A"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_B) withId:@"GostR3410-2001-CryptoPro-B"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_C) withId:@"GostR3410-2001-CryptoPro-C"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchA) withId:@"GostR3410-2001-CryptoPro-XchA"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3410_2001_CryptoPro_XchB) withId:@"GostR3410-2001-CryptoPro-XchB"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_256_paramSetA) withId:@"Tc26-Gost-3410-12-256-paramSetA"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetA) withId:@"Tc26-Gost-3410-12-512-paramSetA"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetB) withId:@"Tc26-Gost-3410-12-512-paramSetB"];
      (void) [LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names putWithId:JreLoadStatic(LibOrgBouncycastleAsn1RosstandartRosstandartObjectIdentifiers, id_tc26_gost_3410_12_512_paramSetC) withId:@"Tc26-Gost-3410-12-512-paramSetC"];
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves)
  }
}

@end

void LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_init(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves *self) {
  NSObject_init(self);
}

LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves *new_LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves, init)
}

LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves *create_LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves, init)
}

LibOrgBouncycastleCryptoParamsECDomainParameters *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_initialize();
  return (LibOrgBouncycastleCryptoParamsECDomainParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params)) getWithId:oid], [LibOrgBouncycastleCryptoParamsECDomainParameters class]);
}

id<JavaUtilEnumeration> LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNames() {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_initialize();
  return [((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names)) elements];
}

LibOrgBouncycastleCryptoParamsECDomainParameters *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByNameWithNSString_(NSString *name) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_initialize();
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds)) getWithId:name], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  if (oid != nil) {
    return (LibOrgBouncycastleCryptoParamsECDomainParameters *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_params)) getWithId:oid], [LibOrgBouncycastleCryptoParamsECDomainParameters class]);
  }
  return nil;
}

NSString *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_initialize();
  return (NSString *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_names)) getWithId:oid], [NSString class]);
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getOIDWithNSString_(NSString *name) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_initialize();
  return (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((JavaUtilHashtable *) nil_chk(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_objIds)) getWithId:name], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves)