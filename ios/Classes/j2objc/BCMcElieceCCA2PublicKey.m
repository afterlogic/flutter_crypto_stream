//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/BCMcElieceCCA2PublicKey.java
//

#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "AsymmetricKeyParameter.h"
#include "BCMcElieceCCA2PublicKey.h"
#include "GF2Matrix.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "McElieceCCA2PublicKey.h"
#include "McElieceCCA2PublicKeyParameters.h"
#include "PQCObjectIdentifiers.h"
#include "PqcJcajceMcelieceUtils.h"
#include "SubjectPublicKeyInfo.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey () {
 @public
  LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey, params_, LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *)

inline jlong LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_get_serialVersionUID(void);
#define LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_serialVersionUID 1LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey, serialVersionUID, jlong)

@implementation LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey

- (instancetype)initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters:(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *)params {
  LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_(self, params);
  return self;
}

- (NSString *)getAlgorithm {
  return @"McEliece-CCA2";
}

- (jint)getN {
  return [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getN];
}

- (jint)getK {
  return [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getK];
}

- (jint)getT {
  return [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getT];
}

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getG {
  return [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getG];
}

- (NSString *)description {
  NSString *result = @"McEliecePublicKey:\n";
  (void) JreStrAppendStrong(&result, "$IC", @" length of the code         : ", [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getN], 0x000a);
  (void) JreStrAppendStrong(&result, "$IC", @" error correction capability: ", [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getT], 0x000a);
  (void) JreStrAppendStrong(&result, "$$", @" generator matrix           : ", [((LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *) nil_chk([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getG])) description]);
  return result;
}

- (jboolean)isEqual:(id)other {
  if (other == nil || !([other isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey class]])) {
    return false;
  }
  LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey *otherKey = (LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey *) cast_chk(other, [LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey class]);
  return ([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getN] == [otherKey getN]) && ([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getT] == [otherKey getT]) && ([((LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *) nil_chk([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getG])) isEqual:[otherKey getG]]);
}

- (NSUInteger)hash {
  return 37 * ([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getN] + 37 * [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getT]) + ((jint) [((LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *) nil_chk([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getG])) hash]);
}

- (IOSByteArray *)getEncoded {
  LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey *key = new_LibOrgBouncycastlePqcAsn1McElieceCCA2PublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getN], [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getT], [((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getG], LibOrgBouncycastlePqcJcajceProviderMceliecePqcJcajceMcelieceUtils_getDigAlgIdWithNSString_([((LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *) nil_chk(params_)) getDigest]));
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmIdentifier = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(JreLoadStatic(LibOrgBouncycastlePqcAsn1PQCObjectIdentifiers, mcElieceCca2));
  @try {
    LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *subjectPublicKeyInfo = new_LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(algorithmIdentifier, key);
    return [subjectPublicKeyInfo getEncoded];
  }
  @catch (JavaIoIOException *e) {
    return nil;
  }
}

- (NSString *)getFormat {
  return @"X.509";
}

- (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)getKeyParams {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters:);
  methods[1].selector = @selector(getAlgorithm);
  methods[2].selector = @selector(getN);
  methods[3].selector = @selector(getK);
  methods[4].selector = @selector(getT);
  methods[5].selector = @selector(getG);
  methods[6].selector = @selector(description);
  methods[7].selector = @selector(isEqual:);
  methods[8].selector = @selector(hash);
  methods[9].selector = @selector(getEncoded);
  methods[10].selector = @selector(getFormat);
  methods[11].selector = @selector(getKeyParams);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "params_", "LLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters;", "toString", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey = { "BCMcElieceCCA2PublicKey", "lib.org.bouncycastle.pqc.jcajce.provider.mceliece", ptrTable, methods, fields, 7, 0x1, 12, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey;
}

@end

void LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey *self, LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *params) {
  NSObject_init(self);
  self->params_ = params;
}

LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey *new_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey, initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_, params)
}

LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey *create_LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey_initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_(LibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey, initWithLibOrgBouncycastlePqcCryptoMcelieceMcElieceCCA2PublicKeyParameters_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcElieceCCA2PublicKey)