//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/srp/SRP6StandardGroups.java
//

#include "Hex.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SRP6GroupParameters.h"
#include "SRP6StandardGroups.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups ()

+ (JavaMathBigInteger *)fromHexWithNSString:(NSString *)hex;

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)fromNGWithNSString:(NSString *)hexN
                                                             withNSString:(NSString *)hexG;

@end

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_1024_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_N = @"EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1024_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_1024_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_g = @"02";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1024_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_1536_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_N = @"9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1536_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_1536_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_g = @"02";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1536_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_2048_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_N = @"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_2048_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_2048_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_g = @"02";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_2048_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_3072_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_N = @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_3072_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_3072_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_g = @"05";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_3072_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_4096_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_N = @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_4096_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_4096_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_g = @"05";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_4096_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_6144_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_N = @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_6144_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_6144_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_g = @"05";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_6144_g, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_8192_N(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_N = @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_8192_N, NSString *)

inline NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_get_rfc5054_8192_g(void);
static NSString *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_g = @"13";
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_8192_g, NSString *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromHexWithNSString_(NSString *hex);

__attribute__((unused)) static LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(NSString *hexN, NSString *hexG);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups)

LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144;
LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192;

@implementation LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_1024 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_1536 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_2048 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_3072 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_4096 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_6144 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144;
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)rfc5054_8192 {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (JavaMathBigInteger *)fromHexWithNSString:(NSString *)hex {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromHexWithNSString_(hex);
}

+ (LibOrgBouncycastleCryptoParamsSRP6GroupParameters *)fromNGWithNSString:(NSString *)hexN
                                                             withNSString:(NSString *)hexG {
  return LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(hexN, hexG);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", 0xa, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(fromHexWithNSString:);
  methods[2].selector = @selector(fromNGWithNSString:withNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "rfc5054_1024_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
    { "rfc5054_1024_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "rfc5054_1024", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 6, -1, -1 },
    { "rfc5054_1536_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 7, -1, -1 },
    { "rfc5054_1536_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
    { "rfc5054_1536", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 9, -1, -1 },
    { "rfc5054_2048_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 10, -1, -1 },
    { "rfc5054_2048_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "rfc5054_2048", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 12, -1, -1 },
    { "rfc5054_3072_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "rfc5054_3072_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "rfc5054_3072", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "rfc5054_4096_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 16, -1, -1 },
    { "rfc5054_4096_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 17, -1, -1 },
    { "rfc5054_4096", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 18, -1, -1 },
    { "rfc5054_6144_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 19, -1, -1 },
    { "rfc5054_6144_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 20, -1, -1 },
    { "rfc5054_6144", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 21, -1, -1 },
    { "rfc5054_8192_N", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "rfc5054_8192_g", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "rfc5054_8192", "LLibOrgBouncycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x19, -1, 24, -1, -1 },
  };
  static const void *ptrTable[] = { "fromHex", "LNSString;", "fromNG", "LNSString;LNSString;", &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_N, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_g, &LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192 };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups = { "SRP6StandardGroups", "lib.org.bouncycastle.crypto.agreement.srp", ptrTable, methods, fields, 7, 0x1, 3, 21, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups class]) {
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1024_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_1536_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_2048_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_3072_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_4096_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_6144_g);
    LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192 = LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_N, LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_rfc5054_8192_g);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups)
  }
}

@end

void LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_init(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups *new_LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, init)
}

LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups *create_LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromHexWithNSString_(NSString *hex) {
  LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_initialize();
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(hex));
}

LibOrgBouncycastleCryptoParamsSRP6GroupParameters *LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromNGWithNSString_withNSString_(NSString *hexN, NSString *hexG) {
  LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_initialize();
  return new_LibOrgBouncycastleCryptoParamsSRP6GroupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromHexWithNSString_(hexN), LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups_fromHexWithNSString_(hexG));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementSrpSRP6StandardGroups)
