//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RSACoreEngine.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "DataLengthException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "RSACoreEngine.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateCrtKeyParameters.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoEnginesRSACoreEngine () {
 @public
  LibOrgBouncycastleCryptoParamsRSAKeyParameters *key_;
  jboolean forEncryption_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRSACoreEngine, key_, LibOrgBouncycastleCryptoParamsRSAKeyParameters *)

@implementation LibOrgBouncycastleCryptoEnginesRSACoreEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesRSACoreEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    key_ = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getParameters], [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
  }
  else {
    key_ = (LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class]);
  }
  self->forEncryption_ = forEncryption;
}

- (jint)getInputBlockSize {
  jint bitSize = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus])) bitLength];
  if (forEncryption_) {
    return (bitSize + 7) / 8 - 1;
  }
  else {
    return (bitSize + 7) / 8;
  }
}

- (jint)getOutputBlockSize {
  jint bitSize = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus])) bitLength];
  if (forEncryption_) {
    return (bitSize + 7) / 8;
  }
  else {
    return (bitSize + 7) / 8 - 1;
  }
}

- (JavaMathBigInteger *)convertInputWithByteArray:(IOSByteArray *)inArg
                                          withInt:(jint)inOff
                                          withInt:(jint)inLen {
  if (inLen > ([self getInputBlockSize] + 1)) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for RSA cipher.");
  }
  else if (inLen == ([self getInputBlockSize] + 1) && !forEncryption_) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for RSA cipher.");
  }
  IOSByteArray *block;
  if (inOff != 0 || inLen != ((IOSByteArray *) nil_chk(inArg))->size_) {
    block = [IOSByteArray newArrayWithLength:inLen];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, block, 0, inLen);
  }
  else {
    block = inArg;
  }
  JavaMathBigInteger *res = new_JavaMathBigInteger_initWithInt_withByteArray_(1, block);
  if ([res compareToWithId:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus]] >= 0) {
    @throw new_LibOrgBouncycastleCryptoDataLengthException_initWithNSString_(@"input too large for RSA cipher.");
  }
  return res;
}

- (IOSByteArray *)convertOutputWithJavaMathBigInteger:(JavaMathBigInteger *)result {
  IOSByteArray *output = [((JavaMathBigInteger *) nil_chk(result)) toByteArray];
  if (forEncryption_) {
    if (IOSByteArray_Get(nil_chk(output), 0) == 0 && output->size_ > [self getOutputBlockSize]) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:output->size_ - 1];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 1, tmp, 0, tmp->size_);
      return tmp;
    }
    if (output->size_ < [self getOutputBlockSize]) {
      IOSByteArray *tmp = [IOSByteArray newArrayWithLength:[self getOutputBlockSize]];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 0, tmp, tmp->size_ - output->size_, output->size_);
      return tmp;
    }
    return output;
  }
  else {
    IOSByteArray *rv;
    if (IOSByteArray_Get(nil_chk(output), 0) == 0) {
      rv = [IOSByteArray newArrayWithLength:output->size_ - 1];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 1, rv, 0, rv->size_);
    }
    else {
      rv = [IOSByteArray newArrayWithLength:output->size_];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(output, 0, rv, 0, rv->size_);
    }
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(output, (jbyte) 0);
    return rv;
  }
}

- (JavaMathBigInteger *)processBlockWithJavaMathBigInteger:(JavaMathBigInteger *)input {
  if ([key_ isKindOfClass:[LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters class]]) {
    LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *crtKey = (LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *) key_;
    JavaMathBigInteger *p = [((LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters *) nil_chk(crtKey)) getP];
    JavaMathBigInteger *q = [crtKey getQ];
    JavaMathBigInteger *dP = [crtKey getDP];
    JavaMathBigInteger *dQ = [crtKey getDQ];
    JavaMathBigInteger *qInv = [crtKey getQInv];
    JavaMathBigInteger *mP;
    JavaMathBigInteger *mQ;
    JavaMathBigInteger *h;
    JavaMathBigInteger *m;
    mP = [((JavaMathBigInteger *) nil_chk(([((JavaMathBigInteger *) nil_chk(input)) remainderWithJavaMathBigInteger:p]))) modPowWithJavaMathBigInteger:dP withJavaMathBigInteger:p];
    mQ = [((JavaMathBigInteger *) nil_chk(([input remainderWithJavaMathBigInteger:q]))) modPowWithJavaMathBigInteger:dQ withJavaMathBigInteger:q];
    h = [((JavaMathBigInteger *) nil_chk(mP)) subtractWithJavaMathBigInteger:mQ];
    h = [((JavaMathBigInteger *) nil_chk(h)) multiplyWithJavaMathBigInteger:qInv];
    h = [((JavaMathBigInteger *) nil_chk(h)) modWithJavaMathBigInteger:p];
    m = [((JavaMathBigInteger *) nil_chk(h)) multiplyWithJavaMathBigInteger:q];
    m = [((JavaMathBigInteger *) nil_chk(m)) addWithJavaMathBigInteger:mQ];
    return m;
  }
  else {
    return [((JavaMathBigInteger *) nil_chk(input)) modPowWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getExponent] withJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus]];
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 6, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getInputBlockSize);
  methods[3].selector = @selector(getOutputBlockSize);
  methods[4].selector = @selector(convertInputWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(convertOutputWithJavaMathBigInteger:);
  methods[6].selector = @selector(processBlockWithJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "key_", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "convertInput", "[BII", "convertOutput", "LJavaMathBigInteger;", "processBlock" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesRSACoreEngine = { "RSACoreEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x0, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesRSACoreEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesRSACoreEngine_init(LibOrgBouncycastleCryptoEnginesRSACoreEngine *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoEnginesRSACoreEngine *new_LibOrgBouncycastleCryptoEnginesRSACoreEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesRSACoreEngine, init)
}

LibOrgBouncycastleCryptoEnginesRSACoreEngine *create_LibOrgBouncycastleCryptoEnginesRSACoreEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesRSACoreEngine, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesRSACoreEngine)
