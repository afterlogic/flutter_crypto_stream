//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/util/PqcSubjectPublicKeyInfoFactory.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NHPublicKeyParameters.h"
#include "PQCObjectIdentifiers.h"
#include "PqcCryptoUtilUtils.h"
#include "PqcSubjectPublicKeyInfoFactory.h"
#include "QTESLAPublicKeyParameters.h"
#include "SPHINCS256KeyParams.h"
#include "SPHINCSPublicKeyParameters.h"
#include "SubjectPublicKeyInfo.h"
#include "XMSSKeyParams.h"
#include "XMSSMTKeyParams.h"
#include "XMSSMTParameters.h"
#include "XMSSMTPublicKey.h"
#include "XMSSMTPublicKeyParameters.h"
#include "XMSSParameters.h"
#include "XMSSPublicKey.h"
#include "XMSSPublicKeyParameters.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init(LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *self);

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *new_LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *create_LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init(void);

@implementation LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(publicKey);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", 0x9, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createSubjectPublicKeyInfo", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory = { "PqcSubjectPublicKeyInfoFactory", "lib.org.bouncycastle.pqc.crypto.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory;
}

@end

void LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init(LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *new_LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory, init)
}

LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory *create_LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory, init)
}

LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_createSubjectPublicKeyInfoWithLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *publicKey) {
  LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory_initialize();
  if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_qTeslaLookupAlgIDWithInt_([((LibOrgBouncycastlePqcCryptoQteslaQTESLAPublicKeyParameters *) nil_chk(keyParams)) getSecurityCategory]);
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(algorithmIdentifier, [keyParams getPublicData]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *params = (LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, sphincs256), new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_sphincs256LookupTreeAlgIDWithNSString_([((LibOrgBouncycastlePqcCryptoSphincsSPHINCSPublicKeyParameters *) nil_chk(params)) getTreeDigest])));
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(algorithmIdentifier, [params getKeyData]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *params = (LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, newHope));
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(algorithmIdentifier, [((LibOrgBouncycastlePqcCryptoNewhopeNHPublicKeyParameters *) nil_chk(params)) getPubData]);
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss), new_LibOrgBouncycastlePqcAsn1XMSSKeyParams_initWithInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *) nil_chk(keyParams)) getParameters])) getHeight], LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_xmssLookupTreeAlgIDWithNSString_([keyParams getTreeDigest])));
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, new_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_([keyParams getPublicSeed], [keyParams getRoot]));
  }
  else if ([publicKey isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters class]]) {
    LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *keyParams = (LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *) publicKey;
    LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, xmss_mt), new_LibOrgBouncycastlePqcAsn1XMSSMTKeyParams_initWithInt_withInt_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSMTPublicKeyParameters *) nil_chk(keyParams)) getParameters])) getHeight], [((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk([keyParams getParameters])) getLayers], LibOrgBouncycastlePqcCryptoUtilPqcCryptoUtilUtils_xmssLookupTreeAlgIDWithNSString_([keyParams getTreeDigest])));
    return new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, new_LibOrgBouncycastlePqcAsn1XMSSMTPublicKey_initWithByteArray_withByteArray_([keyParams getPublicSeed], [keyParams getRoot]));
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"key parameters not recognized");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoUtilPqcSubjectPublicKeyInfoFactory)
