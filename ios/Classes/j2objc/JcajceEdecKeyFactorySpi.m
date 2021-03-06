//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/edec/JcajceEdecKeyFactorySpi.java
//

#include "ASN1Encodable.h"
#include "ASN1InputStream.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "BCEdDSAPrivateKey.h"
#include "BCEdDSAPublicKey.h"
#include "BCXDHPrivateKey.h"
#include "BCXDHPublicKey.h"
#include "BaseKeyFactorySpi.h"
#include "CipherParameters.h"
#include "DEROctetString.h"
#include "Ed25519PrivateKeyParameters.h"
#include "Ed25519PublicKeyParameters.h"
#include "EdECObjectIdentifiers.h"
#include "Hex.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceEdecKeyFactorySpi.h"
#include "OpenSSHPrivateKeySpec.h"
#include "OpenSSHPrivateKeyUtil.h"
#include "OpenSSHPublicKeySpec.h"
#include "OpenSSHPublicKeyUtil.h"
#include "PrivateKeyInfo.h"
#include "SubjectPublicKeyInfo.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Throwable.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "java/security/spec/X509EncodedKeySpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi () {
 @public
  jboolean isXdh_;
  jint specificBase_;
}

@end

inline jbyte LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_x448_type(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type 111
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, x448_type, jbyte)

inline jbyte LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_x25519_type(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type 110
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, x25519_type, jbyte)

inline jbyte LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_Ed448_type(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type 113
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, Ed448_type, jbyte)

inline jbyte LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_get_Ed25519_type(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type 112
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, Ed25519_type, jbyte)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi)

IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix;
IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix;
IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix;
IOSByteArray *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix;

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi

+ (IOSByteArray *)x448Prefix {
  return LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix;
}

+ (IOSByteArray *)x25519Prefix {
  return LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix;
}

+ (IOSByteArray *)Ed448Prefix {
  return LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix;
}

+ (IOSByteArray *)Ed25519Prefix {
  return LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix;
}

- (instancetype)initWithNSString:(NSString *)algorithm
                     withBoolean:(jboolean)isXdh
                         withInt:(jint)specificBase {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, algorithm, isXdh, specificBase);
  return self;
}

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"key type unknown");
}

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec {
  if ([((IOSClass *) nil_chk(spec)) isAssignableFrom:LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec_class_()] && [key isKindOfClass:[LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPrivateKey class]]) {
    @try {
      LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
      LibOrgBouncycastleAsn1DEROctetString *val = (LibOrgBouncycastleAsn1DEROctetString *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:2], [LibOrgBouncycastleAsn1DEROctetString class]);
      LibOrgBouncycastleAsn1ASN1InputStream *in = new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_([((LibOrgBouncycastleAsn1DEROctetString *) nil_chk(val)) getOctets]);
      return new_LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec_initWithByteArray_(LibOrgBouncycastleCryptoUtilOpenSSHPrivateKeyUtil_encodePrivateKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithByteArray_withInt_([((LibOrgBouncycastleAsn1DEROctetString *) nil_chk(((LibOrgBouncycastleAsn1DEROctetString *) cast_chk([in readObject], [LibOrgBouncycastleAsn1DEROctetString class])))) getOctets], 0)));
    }
    @catch (JavaIoIOException *ex) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_withJavaLangThrowable_([ex getMessage], [ex getCause]);
    }
  }
  else if ([spec isAssignableFrom:LibOrgBouncycastleJceSpecOpenSSHPublicKeySpec_class_()] && [key isKindOfClass:[LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey class]]) {
    @try {
      return new_LibOrgBouncycastleJceSpecOpenSSHPublicKeySpec_initWithByteArray_(LibOrgBouncycastleCryptoUtilOpenSSHPublicKeyUtil_encodePublicKeyWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(new_LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters_initWithByteArray_withInt_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded], ((IOSByteArray *) nil_chk(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix))->size_)));
    }
    @catch (JavaIoIOException *ex) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_withJavaLangThrowable_([ex getMessage], [ex getCause]);
    }
  }
  return [super engineGetKeySpecWithJavaSecurityKey:key withIOSClass:spec];
}

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec class]]) {
    id<LibOrgBouncycastleCryptoCipherParameters> parameters = LibOrgBouncycastleCryptoUtilOpenSSHPrivateKeyUtil_parsePrivateKeyBlobWithByteArray_([((LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec *) nil_chk(((LibOrgBouncycastleJceSpecOpenSSHPrivateKeySpec *) keySpec))) getEncoded]);
    if ([parameters isKindOfClass:[LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters class]]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_((LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) parameters);
    }
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"openssh private key not Ed25519 private key");
  }
  return [super engineGeneratePrivateWithJavaSecuritySpecKeySpec:keySpec];
}

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecX509EncodedKeySpec class]]) {
    IOSByteArray *enc = [((JavaSecuritySpecX509EncodedKeySpec *) nil_chk(((JavaSecuritySpecX509EncodedKeySpec *) keySpec))) getEncoded];
    if (specificBase_ == 0 || specificBase_ == IOSByteArray_Get(nil_chk(enc), 8)) {
      switch (IOSByteArray_Get(nil_chk(enc), 8)) {
        case LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type:
        return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPublicKey_initWithByteArray_withByteArray_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix, enc);
        case LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type:
        return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPublicKey_initWithByteArray_withByteArray_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix, enc);
        case LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type:
        return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey_initWithByteArray_withByteArray_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix, enc);
        case LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type:
        return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey_initWithByteArray_withByteArray_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix, enc);
        default:
        return [super engineGeneratePublicWithJavaSecuritySpecKeySpec:keySpec];
      }
    }
  }
  else if ([keySpec isKindOfClass:[LibOrgBouncycastleJceSpecOpenSSHPublicKeySpec class]]) {
    id<LibOrgBouncycastleCryptoCipherParameters> parameters = LibOrgBouncycastleCryptoUtilOpenSSHPublicKeyUtil_parsePublicKeyWithByteArray_([((LibOrgBouncycastleJceSpecOpenSSHPublicKeySpec *) nil_chk(((LibOrgBouncycastleJceSpecOpenSSHPublicKeySpec *) keySpec))) getEncoded]);
    if ([parameters isKindOfClass:[LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters class]]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey_initWithByteArray_withByteArray_([IOSByteArray newArrayWithLength:0], [((LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) nil_chk(((LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) parameters))) getEncoded]);
    }
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"openssh public key not Ed25519 public key");
  }
  return [super engineGeneratePublicWithJavaSecuritySpecKeySpec:keySpec];
}

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algOid = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(keyInfo)) getPrivateKeyAlgorithm])) getAlgorithm];
  if (isXdh_) {
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type) && [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X448)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
    }
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type) && [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X25519)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
    }
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed448)] || [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed25519)]) {
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type) && [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed448)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
    }
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type) && [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed25519)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
    }
  }
  @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@$", @"algorithm identifier ", algOid, @" in key not recognized"));
}

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algOid = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(keyInfo)) getAlgorithm])) getAlgorithm];
  if (isXdh_) {
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type) && [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X448)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
    }
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type) && [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_X25519)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCXDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
    }
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(algOid)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed448)] || [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed25519)]) {
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type) && [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed448)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
    }
    if ((specificBase_ == 0 || specificBase_ == LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type) && [algOid isEqual:JreLoadStatic(LibOrgBouncycastleAsn1EdecEdECObjectIdentifiers, id_Ed25519)]) {
      return new_LibOrgBouncycastleJcajceProviderAsymmetricEdecBCEdDSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
    }
  }
  @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@$", @"algorithm identifier ", algOid, @" in key not recognized"));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x4, 1, 2, 3, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x4, 4, 5, 6, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x4, 7, 8, 6, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x4, 9, 8, 6, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, 10, 11, 12, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, 13, 14, 12, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withBoolean:withInt:);
  methods[1].selector = @selector(engineTranslateKeyWithJavaSecurityKey:);
  methods[2].selector = @selector(engineGetKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[3].selector = @selector(engineGeneratePrivateWithJavaSecuritySpecKeySpec:);
  methods[4].selector = @selector(engineGeneratePublicWithJavaSecuritySpecKeySpec:);
  methods[5].selector = @selector(generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[6].selector = @selector(generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x448Prefix", "[B", .constantValue.asLong = 0, 0x18, -1, 15, -1, -1 },
    { "x25519Prefix", "[B", .constantValue.asLong = 0, 0x18, -1, 16, -1, -1 },
    { "Ed448Prefix", "[B", .constantValue.asLong = 0, 0x18, -1, 17, -1, -1 },
    { "Ed25519Prefix", "[B", .constantValue.asLong = 0, 0x18, -1, 18, -1, -1 },
    { "x448_type", "B", .constantValue.asChar = LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type, 0x1a, -1, -1, -1, -1 },
    { "x25519_type", "B", .constantValue.asChar = LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type, 0x1a, -1, -1, -1, -1 },
    { "Ed448_type", "B", .constantValue.asChar = LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type, 0x1a, -1, -1, -1, -1 },
    { "Ed25519_type", "B", .constantValue.asChar = LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type, 0x1a, -1, -1, -1, -1 },
    { "algorithm_", "LNSString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "isXdh_", "Z", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "specificBase_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;ZI", "engineTranslateKey", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;", "engineGetKeySpec", "LJavaSecurityKey;LIOSClass;", "LJavaSecuritySpecInvalidKeySpecException;", "engineGeneratePrivate", "LJavaSecuritySpecKeySpec;", "engineGeneratePublic", "generatePrivate", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "generatePublic", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", &LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix, &LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix, &LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix, &LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix, "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH;LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448;LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519;LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA;LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448;LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi = { "JcajceEdecKeyFactorySpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, fields, 7, 0x1, 7, 11, -1, 19, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi class]) {
    LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448Prefix = LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"3042300506032b656f033900");
    LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519Prefix = LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"302a300506032b656e032100");
    LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448Prefix = LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"3043300506032b6571033a00");
    LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519Prefix = LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_(@"302a300506032b6570032100");
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi)
  }
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *self, NSString *algorithm, jboolean isXdh, jint specificBase) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi_init(self);
  self->algorithm_ = algorithm;
  self->isXdh_ = isXdh;
  self->specificBase_ = specificBase;
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(NSString *algorithm, jboolean isXdh, jint specificBase) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, initWithNSString_withBoolean_withInt_, algorithm, isXdh, specificBase)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(NSString *algorithm, jboolean isXdh, jint specificBase) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi, initWithNSString_withBoolean_withInt_, algorithm, isXdh, specificBase)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH = { "XDH", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"XDH", true, 0);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_XDH)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 = { "X448", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"X448", true, LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x448_type);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X448)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 = { "X25519", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"X25519", true, LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_x25519_type);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_X25519)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA = { "EDDSA", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"EdDSA", false, 0);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_EDDSA)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 = { "ED448", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"Ed448", false, LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed448_type);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED448)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init(self);
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
  static const void *ptrTable[] = { "LLibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 = { "ED25519", "lib.org.bouncycastle.jcajce.provider.asymmetric.edec", ptrTable, methods, NULL, 7, 0x9, 1, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_initWithNSString_withBoolean_withInt_(self, @"Ed25519", false, LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_Ed25519_type);
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519 *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecKeyFactorySpi_ED25519)
