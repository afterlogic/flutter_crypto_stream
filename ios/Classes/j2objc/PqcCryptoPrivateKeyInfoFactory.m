//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/util/PqcCryptoPrivateKeyInfoFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "ASN1Set.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "DEROctetString.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NHPrivateKeyParameters.h"
#include "PQCObjectIdentifiers.h"
#include "Pack.h"
#include "PqcAsn1XMSSMTPrivateKey.h"
#include "PqcAsn1XMSSPrivateKey.h"
#include "PqcCryptoPrivateKeyInfoFactory.h"
#include "PqcCryptoUtilUtils.h"
#include "PrivateKeyInfo.h"
#include "QTESLAPrivateKeyParameters.h"
#include "SPHINCS256KeyParams.h"
#include "SPHINCSPrivateKeyParameters.h"
#include "XMSSKeyParams.h"
#include "XMSSMTKeyParams.h"
#include "XMSSMTParameters.h"
#include "XMSSMTPrivateKeyParameters.h"
#include "XMSSParameters.h"
#include "XMSSPrivateKeyParameters.h"
#include "XMSSUtil.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory ()

- (instancetype)init;

+ (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey *)xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *)keyParams;

+ (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *)xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)keyParams;

@end

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *self);

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *new_LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *create_LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init(void);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams);

@implementation LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey {
  return LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(privateKey);
}

+ (LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                                         withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)attributes {
  return LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleAsn1ASN1Set_(privateKey, attributes);
}

+ (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey *)xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *)keyParams {
  return LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(keyParams);
}

+ (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *)xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)keyParams {
  return LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(keyParams);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", 0x9, 0, 3, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey;", 0xa, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey;", 0xa, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  methods[2].selector = @selector(createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[3].selector = @selector(xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters:);
  methods[4].selector = @selector(xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createPrivateKeyInfo", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "LJavaIoIOException;", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;LLibOrgBouncycastleAsn1ASN1Set;", "xmssCreateKeyStructure", "LLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters;", "xmssmtCreateKeyStructure", "LLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory = { "PqcCryptoPrivateKeyInfoFactory", "lib.org.bouncycastle.pqc.crypto.util", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory;
}

@end

void LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *new_LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory, init)
}

LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory *create_LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory, init)
}

LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey) {
  LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_initialize();
  return LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleAsn1ASN1Set_(privateKey, nil);
}

LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_createPrivateKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *privateKey, LibOrgBouncycastleAsn1ASN1Set *attributes) {
  LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_initialize();
  if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcCryptoQteslaQTESLAPrivateKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoQteslaQTESLAPrivateKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoQteslaQTESLAPrivateKeyParameters *) privateKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_qTeslaLookupAlgIDWithInt_([((LibOrgBouncycastlePqcCryptoQteslaQTESLAPrivateKeyParameters *) nil_chk(keyParams)) getSecurityCategory]);
    return new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_withLibOrgBouncycastleAsn1ASN1Set_(algorithmIdentifier, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([keyParams getSecret]), attributes);
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *params = (LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *) privateKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, sphincs256), new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_sphincs256LookupTreeAlgIDWithNSString_([((LibOrgBouncycastlePqcCryptoSphincsSPHINCSPrivateKeyParameters *) nil_chk(params)) getTreeDigest])));
    return new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([params getKeyData]));
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *params = (LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *) privateKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, newHope));
    IOSShortArray *privateKeyData = [((LibOrgBouncycastlePqcCryptoNewhopeNHPrivateKeyParameters *) nil_chk(params)) getSecData];
    IOSByteArray *octets = [IOSByteArray newArrayWithLength:((IOSShortArray *) nil_chk(privateKeyData))->size_ * 2];
    for (jint i = 0; i != privateKeyData->size_; i++) {
      LibOrgBouncycastleUtilPack_shortToLittleEndianWithShort_withByteArray_withInt_(IOSShortArray_Get(privateKeyData, i), octets, i * 2);
    }
    return new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(octets));
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *) privateKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss), new_LibOrgBouncycastlePqcAsn1XMSSKeyParams_initWithInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(keyParams)) getParameters])) getHeight], LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_xmssLookupTreeAlgIDWithNSString_([keyParams getTreeDigest])));
    return new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(keyParams));
  }
  else if ([privateKey isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) privateKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss_mt), new_LibOrgBouncycastlePqcAsn1XMSSMTKeyParams_initWithInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(keyParams)) getParameters])) getHeight], [((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([keyParams getParameters])) getLayers], LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_xmssLookupTreeAlgIDWithNSString_([keyParams getTreeDigest])));
    return new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(keyParams));
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"key parameters not recognized");
  }
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *keyParams) {
  LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_initialize();
  IOSByteArray *keyData = [((LibOrgBouncycastlePqcCryptoXmssXMSSPrivateKeyParameters *) nil_chk(keyParams)) toByteArray];
  jint n = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([keyParams getParameters])) getDigestSize];
  jint totalHeight = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([keyParams getParameters])) getHeight];
  jint indexSize = 4;
  jint secretKeySize = n;
  jint secretKeyPRFSize = n;
  jint publicSeedSize = n;
  jint rootSize = n;
  jint position = 0;
  jint index = (jint) LibOrgBouncycastlePqcCryptoXmssXMSSUtil_bytesToXBigEndianWithByteArray_withInt_withInt_(keyData, position, indexSize);
  if (!LibOrgBouncycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_(totalHeight, index)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"index out of bounds");
  }
  position += indexSize;
  IOSByteArray *secretKeySeed = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, secretKeySize);
  position += secretKeySize;
  IOSByteArray *secretKeyPRF = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, secretKeyPRFSize);
  position += secretKeyPRFSize;
  IOSByteArray *publicSeed = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, publicSeedSize);
  position += publicSeedSize;
  IOSByteArray *root = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, rootSize);
  position += rootSize;
  IOSByteArray *bdsStateBinary = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, ((IOSByteArray *) nil_chk(keyData))->size_ - position);
  return new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_xmssmtCreateKeyStructureWithLibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *keyParams) {
  LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory_initialize();
  IOSByteArray *keyData = [((LibOrgBouncycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(keyParams)) toByteArray];
  jint n = [((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([keyParams getParameters])) getDigestSize];
  jint totalHeight = [((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([keyParams getParameters])) getHeight];
  jint indexSize = (totalHeight + 7) / 8;
  jint secretKeySize = n;
  jint secretKeyPRFSize = n;
  jint publicSeedSize = n;
  jint rootSize = n;
  jint position = 0;
  jint index = (jint) LibOrgBouncycastlePqcCryptoXmssXMSSUtil_bytesToXBigEndianWithByteArray_withInt_withInt_(keyData, position, indexSize);
  if (!LibOrgBouncycastlePqcCryptoXmssXMSSUtil_isIndexValidWithInt_withLong_(totalHeight, index)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"index out of bounds");
  }
  position += indexSize;
  IOSByteArray *secretKeySeed = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, secretKeySize);
  position += secretKeySize;
  IOSByteArray *secretKeyPRF = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, secretKeyPRFSize);
  position += secretKeyPRFSize;
  IOSByteArray *publicSeed = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, publicSeedSize);
  position += publicSeedSize;
  IOSByteArray *root = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, rootSize);
  position += rootSize;
  IOSByteArray *bdsStateBinary = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(keyData, position, ((IOSByteArray *) nil_chk(keyData))->size_ - position);
  return new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoUtilPqcCryptoPrivateKeyInfoFactory)
