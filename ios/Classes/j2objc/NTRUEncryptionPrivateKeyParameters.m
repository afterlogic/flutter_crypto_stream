//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUEncryptionPrivateKeyParameters.java
//

#include "DenseTernaryPolynomial.h"
#include "IOSPrimitiveArray.h"
#include "IntegerPolynomial.h"
#include "J2ObjC_source.h"
#include "NTRUEncryptionKeyParameters.h"
#include "NTRUEncryptionParameters.h"
#include "NTRUEncryptionPrivateKeyParameters.h"
#include "NTRUParameters.h"
#include "PqcMathPolynomial.h"
#include "ProductFormPolynomial.h"
#include "SparseTernaryPolynomial.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters ()

- (void)init__ OBJC_METHOD_FAMILY_NONE;

@end

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self);

@implementation LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters

- (instancetype)initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                    withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial:(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)t
                    withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)fp
                     withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, h, t, fp, params);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)b
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, b, params);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, is, params);
  return self;
}

- (void)init__ {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(self);
}

- (IOSByteArray *)getEncoded {
  IOSByteArray *hBytes = [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) toBinaryWithInt:((LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params_))->q_];
  IOSByteArray *tBytes;
  if ([t_ isKindOfClass:[LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial class]]) {
    tBytes = [((LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial *) t_))) toBinary];
  }
  else {
    tBytes = [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk([((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(t_)) toIntegerPolynomial])) toBinary3Tight];
  }
  IOSByteArray *res = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(hBytes))->size_ + ((IOSByteArray *) nil_chk(tBytes))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(hBytes, 0, res, 0, hBytes->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(tBytes, 0, res, hBytes->size_, tBytes->size_);
  return res;
}

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os {
  [((JavaIoOutputStream *) nil_chk(os)) writeWithByteArray:[self getEncoded]];
}

- (NSUInteger)hash {
  jint prime = 31;
  jint result = 1;
  result = prime * result + ((params_ == nil) ? 0 : ((jint) [((LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params_)) hash]));
  result = prime * result + ((t_ == nil) ? 0 : ((jint) [((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(t_)) hash]));
  result = prime * result + ((h_ == nil) ? 0 : ((jint) [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) hash]));
  return result;
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (obj == nil) {
    return false;
  }
  if (!([obj isKindOfClass:[LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters class]])) {
    return false;
  }
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *other = (LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *) cast_chk(obj, [LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters class]);
  if (params_ == nil) {
    if (other->params_ != nil) {
      return false;
    }
  }
  else if (![params_ isEqual:other->params_]) {
    return false;
  }
  if (t_ == nil) {
    if (other->t_ != nil) {
      return false;
    }
  }
  else if (![t_ isEqual:other->t_]) {
    return false;
  }
  if (![((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) isEqual:other->h_]) {
    return false;
  }
  return true;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 4, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 2, -1, -1, -1 },
    { NULL, "I", 0x1, 7, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[1].selector = @selector(initWithByteArray:withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[2].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[3].selector = @selector(init__);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(writeToWithJavaIoOutputStream:);
  methods[6].selector = @selector(hash);
  methods[7].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "t_", "LLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "fp_", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "h_", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;LLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;", "[BLLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;", "LJavaIoIOException;", "LJavaIoInputStream;LLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;", "init", "writeTo", "LJavaIoOutputStream;", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters = { "NTRUEncryptionPrivateKeyParameters", "lib.org.bouncycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, true, params);
  self->h_ = h;
  self->t_ = t;
  self->fp_ = fp;
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, h, t, fp, params)
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, h, t, fp, params)
}

void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, new_JavaIoByteArrayInputStream_initWithByteArray_(b), params);
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, b, params)
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, b, params)
}

void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(self, true, params);
  if (((LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params))->polyType_ == LibOrgBouncycastlePqcCryptoNtruNTRUParameters_TERNARY_POLYNOMIAL_TYPE_PRODUCT) {
    jint N = params->N_;
    jint df1 = params->df1_;
    jint df2 = params->df2_;
    jint df3Ones = params->df3_;
    jint df3NegOnes = params->fastFp_ ? params->df3_ : params->df3_ - 1;
    self->h_ = LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_(is, params->N_, params->q_);
    self->t_ = LibOrgBouncycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(is, N, df1, df2, df3Ones, df3NegOnes);
  }
  else {
    self->h_ = LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_(is, params->N_, params->q_);
    LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fInt = LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinary3TightWithJavaIoInputStream_withInt_(is, params->N_);
    self->t_ = params->sparse_ ? new_LibOrgBouncycastlePqcMathNtruPolynomialSparseTernaryPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(fInt) : (id) new_LibOrgBouncycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(fInt);
  }
  LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(self);
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, is, params)
}

LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_, is, params)
}

void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self) {
  if (((LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(self->params_))->fastFp_) {
    self->fp_ = new_LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_initWithInt_(self->params_->N_);
    *IOSIntArray_GetRef(nil_chk(self->fp_->coeffs_), 0) = 1;
  }
  else {
    self->fp_ = [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk([((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(self->t_)) toIntegerPolynomial])) invertF3];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters)
