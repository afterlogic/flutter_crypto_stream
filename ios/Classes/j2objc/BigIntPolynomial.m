//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/BigIntPolynomial.java
//

#include "Arrays.h"
#include "BigDecimalPolynomial.h"
#include "BigIntPolynomial.h"
#include "Constants.h"
#include "CryptoServicesRegistrar.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "IntegerPolynomial.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Math.h"
#include "java/math/BigDecimal.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "java/util/ArrayList.h"
#include "java/util/Collections.h"
#include "java/util/List.h"

@interface LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial ()

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2;

- (JavaMathBigInteger *)maxCoeffAbs;

@end

inline jdouble LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_get_LOG_10_2(void);
static jdouble LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_LOG_10_2;
J2OBJC_STATIC_FIELD_PRIMITIVE_FINAL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, LOG_10_2, jdouble)

__attribute__((unused)) static LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *poly2);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_maxCoeffAbs(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial)

@implementation LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial

- (instancetype)initWithInt:(jint)N {
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(self, N);
  return self;
}

- (instancetype)initWithJavaMathBigIntegerArray:(IOSObjectArray *)coeffs {
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(self, coeffs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)p {
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(self, p);
  return self;
}

+ (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)generateRandomSmallWithInt:(jint)N
                                                                                withInt:(jint)numOnes
                                                                                withInt:(jint)numNegOnes {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_generateRandomSmallWithInt_withInt_withInt_(N, numOnes, numNegOnes);
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2 {
  jint N = ((IOSObjectArray *) nil_chk(coeffs_))->size_;
  if (((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(poly2))->coeffs_->size_ != N) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Number of coefficients must be the same");
  }
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c = LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(self, poly2);
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c))->coeffs_))->size_ > N) {
    for (jint k = N; k < ((IOSObjectArray *) nil_chk(c->coeffs_))->size_; k++) {
      (void) IOSObjectArray_Set(c->coeffs_, k - N, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(c->coeffs_, k - N))) addWithJavaMathBigInteger:IOSObjectArray_Get(c->coeffs_, k)]);
    }
    c->coeffs_ = LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(c->coeffs_, N);
  }
  return c;
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2 {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(self, poly2);
}

- (void)addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)b
                                                withJavaMathBigInteger:(JavaMathBigInteger *)modulus {
  [self addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:b];
  [self modWithJavaMathBigInteger:modulus];
}

- (void)addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)b {
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(b))->coeffs_))->size_ > coeffs_->size_) {
    jint N = coeffs_->size_;
    coeffs_ = LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(coeffs_, b->coeffs_->size_);
    for (jint i = N; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(coeffs_, i, JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO));
    }
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(b->coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) addWithJavaMathBigInteger:IOSObjectArray_Get(b->coeffs_, i)]);
  }
}

- (void)subWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)b {
  if (((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(b))->coeffs_))->size_ > coeffs_->size_) {
    jint N = coeffs_->size_;
    coeffs_ = LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(coeffs_, b->coeffs_->size_);
    for (jint i = N; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(coeffs_, i, JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO));
    }
  }
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(b->coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) subtractWithJavaMathBigInteger:IOSObjectArray_Get(b->coeffs_, i)]);
  }
}

- (void)multWithJavaMathBigInteger:(JavaMathBigInteger *)factor {
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) multiplyWithJavaMathBigInteger:factor]);
  }
}

- (void)multWithInt:(jint)factor {
  [self multWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(factor)];
}

- (void)divWithJavaMathBigInteger:(JavaMathBigInteger *)divisor {
  JavaMathBigInteger *d = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(divisor)) addWithJavaMathBigInteger:JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ONE)])) divideWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(2)];
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) compareToWithId:JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO)] > 0 ? [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(nil_chk(coeffs_), i))) addWithJavaMathBigInteger:d] : [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(nil_chk(coeffs_), i))) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(d)) negate]]);
    (void) IOSObjectArray_Set(nil_chk(coeffs_), i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) divideWithJavaMathBigInteger:divisor]);
  }
}

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)divWithJavaMathBigDecimal:(JavaMathBigDecimal *)divisor
                                                                                   withInt:(jint)decimalPlaces {
  JavaMathBigInteger *max = LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_maxCoeffAbs(self);
  jint coeffLength = JreFpToInt(([((JavaMathBigInteger *) nil_chk(max)) bitLength] * LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_LOG_10_2)) + 1;
  JavaMathBigDecimal *factor = [((JavaMathBigDecimal *) nil_chk(JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGDEC_ONE))) divideWithJavaMathBigDecimal:divisor withInt:coeffLength + decimalPlaces + 1 withInt:JavaMathBigDecimal_ROUND_HALF_EVEN];
  LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *p = new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(((IOSObjectArray *) nil_chk(coeffs_))->size_);
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(nil_chk(p->coeffs_), i, [((JavaMathBigDecimal *) nil_chk([new_JavaMathBigDecimal_initWithJavaMathBigInteger_(IOSObjectArray_Get(coeffs_, i)) multiplyWithJavaMathBigDecimal:factor])) setScaleWithInt:decimalPlaces withInt:JavaMathBigDecimal_ROUND_HALF_EVEN]);
  }
  return p;
}

- (jint)getMaxCoeffLength {
  return JreFpToInt(([((JavaMathBigInteger *) nil_chk(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_maxCoeffAbs(self))) bitLength] * LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_LOG_10_2)) + 1;
}

- (JavaMathBigInteger *)maxCoeffAbs {
  return LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_maxCoeffAbs(self);
}

- (void)modWithJavaMathBigInteger:(JavaMathBigInteger *)modulus {
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(coeffs_, i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(coeffs_, i))) modWithJavaMathBigInteger:modulus]);
  }
}

- (JavaMathBigInteger *)sumCoeffs {
  JavaMathBigInteger *sum = JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO);
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(coeffs_))->size_; i++) {
    sum = [((JavaMathBigInteger *) nil_chk(sum)) addWithJavaMathBigInteger:IOSObjectArray_Get(coeffs_, i)];
  }
  return sum;
}

- (id)java_clone {
  return new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_([((IOSObjectArray *) nil_chk(coeffs_)) java_clone]);
}

- (NSUInteger)hash {
  jint prime = 31;
  jint result = 1;
  result = prime * result + LibOrgBouncycastleUtilArrays_hashCodeWithNSObjectArray_(coeffs_);
  return result;
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (obj == nil) {
    return false;
  }
  if ([self java_getClass] != [obj java_getClass]) {
    return false;
  }
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *other = (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk(obj, [LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial class]);
  if (!LibOrgBouncycastleUtilArrays_areEqualWithNSObjectArray_withNSObjectArray_(coeffs_, other->coeffs_)) {
    return false;
  }
  return true;
}

- (IOSObjectArray *)getCoeffs {
  return LibOrgBouncycastleUtilArrays_cloneWithJavaMathBigIntegerArray_(coeffs_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x8, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", 0x2, 7, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 5, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial;", 0x1, 12, 13, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 11, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 15, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 16, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 17, 18, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithJavaMathBigIntegerArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:);
  methods[3].selector = @selector(generateRandomSmallWithInt:withInt:withInt:);
  methods[4].selector = @selector(multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[5].selector = @selector(multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[6].selector = @selector(addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:withJavaMathBigInteger:);
  methods[7].selector = @selector(addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[8].selector = @selector(subWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:);
  methods[9].selector = @selector(multWithJavaMathBigInteger:);
  methods[10].selector = @selector(multWithInt:);
  methods[11].selector = @selector(divWithJavaMathBigInteger:);
  methods[12].selector = @selector(divWithJavaMathBigDecimal:withInt:);
  methods[13].selector = @selector(getMaxCoeffLength);
  methods[14].selector = @selector(maxCoeffAbs);
  methods[15].selector = @selector(modWithJavaMathBigInteger:);
  methods[16].selector = @selector(sumCoeffs);
  methods[17].selector = @selector(java_clone);
  methods[18].selector = @selector(hash);
  methods[19].selector = @selector(isEqual:);
  methods[20].selector = @selector(getCoeffs);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "LOG_10_2", "D", .constantValue.asLong = 0, 0x1a, -1, 19, -1, -1 },
    { "coeffs_", "[LJavaMathBigInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "[LJavaMathBigInteger;", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", "generateRandomSmall", "III", "mult", "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;", "multRecursive", "add", "LLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;LJavaMathBigInteger;", "sub", "LJavaMathBigInteger;", "div", "LJavaMathBigDecimal;I", "mod", "clone", "hashCode", "equals", "LNSObject;", &LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_LOG_10_2 };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial = { "BigIntPolynomial", "lib.org.bouncycastle.pqc.math.ntru.polynomial", ptrTable, methods, fields, 7, 0x1, 21, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial class]) {
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_LOG_10_2 = JavaLangMath_log10WithDouble_(2);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial)
  }
}

@end

void LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self, jint N) {
  NSObject_init(self);
  self->coeffs_ = [IOSObjectArray newArrayWithLength:N type:JavaMathBigInteger_class_()];
  for (jint i = 0; i < N; i++) {
    (void) IOSObjectArray_Set(self->coeffs_, i, JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO));
  }
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(jint N) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithInt_, N)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(jint N) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithInt_, N)
}

void LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self, IOSObjectArray *coeffs) {
  NSObject_init(self);
  self->coeffs_ = coeffs;
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(IOSObjectArray *coeffs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithJavaMathBigIntegerArray_, coeffs)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(IOSObjectArray *coeffs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithJavaMathBigIntegerArray_, coeffs)
}

void LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p) {
  NSObject_init(self);
  self->coeffs_ = [IOSObjectArray newArrayWithLength:((IOSIntArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(p))->coeffs_))->size_ type:JavaMathBigInteger_class_()];
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(self->coeffs_))->size_; i++) {
    (void) IOSObjectArray_Set(self->coeffs_, i, JavaMathBigInteger_valueOfWithLong_(IOSIntArray_Get(nil_chk(p->coeffs_), i)));
  }
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_, p)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial, initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_, p)
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_generateRandomSmallWithInt_withInt_withInt_(jint N, jint numOnes, jint numNegOnes) {
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initialize();
  id<JavaUtilList> coeffs = new_JavaUtilArrayList_init();
  for (jint i = 0; i < numOnes; i++) {
    [coeffs addWithId:JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ONE)];
  }
  for (jint i = 0; i < numNegOnes; i++) {
    [coeffs addWithId:JavaMathBigInteger_valueOfWithLong_(-1)];
  }
  while ([coeffs size] < N) {
    [coeffs addWithId:JreLoadStatic(LibOrgBouncycastlePqcMathNtruPolynomialConstants, BIGINT_ZERO)];
  }
  JavaUtilCollections_shuffleWithJavaUtilList_withJavaUtilRandom_(coeffs, LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom());
  LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *poly = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(N);
  for (jint i = 0; i < [coeffs size]; i++) {
    (void) IOSObjectArray_Set(nil_chk(poly->coeffs_), i, (JavaMathBigInteger *) cast_chk([coeffs getWithInt:i], [JavaMathBigInteger class]));
  }
  return poly;
}

LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *poly2) {
  IOSObjectArray *a = self->coeffs_;
  IOSObjectArray *b = ((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(poly2))->coeffs_;
  jint n = ((IOSObjectArray *) nil_chk(poly2->coeffs_))->size_;
  if (n <= 1) {
    IOSObjectArray *c = LibOrgBouncycastleUtilArrays_cloneWithJavaMathBigIntegerArray_(self->coeffs_);
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(self->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(nil_chk(c), i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(c, i))) multiplyWithJavaMathBigInteger:IOSObjectArray_Get(poly2->coeffs_, 0)]);
    }
    return new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(c);
  }
  else {
    jint n1 = n / 2;
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *a1 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(a, n1));
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *a2 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(LibOrgBouncycastleUtilArrays_copyOfRangeWithJavaMathBigIntegerArray_withInt_withInt_(a, n1, n));
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *b1 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(LibOrgBouncycastleUtilArrays_copyOfWithJavaMathBigIntegerArray_withInt_(b, n1));
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *b2 = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithJavaMathBigIntegerArray_(LibOrgBouncycastleUtilArrays_copyOfRangeWithJavaMathBigIntegerArray_withInt_withInt_(b, n1, n));
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *A = (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([a1 java_clone], [LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial class]);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(A)) addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:a2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *B = (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([b1 java_clone], [LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial class]);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(B)) addWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:b2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c1 = LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(a1, b1);
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c2 = LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(a2, b2);
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c3 = LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_multRecursiveWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(A, B);
    [((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c3)) subWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:c1];
    [c3 subWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:c2];
    LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *c = new_LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_initWithInt_(2 * n - 1);
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c1))->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, i, IOSObjectArray_Get(c1->coeffs_, i));
    }
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(c3->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, n1 + i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(c->coeffs_, n1 + i))) addWithJavaMathBigInteger:IOSObjectArray_Get(c3->coeffs_, i)]);
    }
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(((LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(c2))->coeffs_))->size_; i++) {
      (void) IOSObjectArray_Set(c->coeffs_, 2 * n1 + i, [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(c->coeffs_, 2 * n1 + i))) addWithJavaMathBigInteger:IOSObjectArray_Get(c2->coeffs_, i)]);
    }
    return c;
  }
}

JavaMathBigInteger *LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_maxCoeffAbs(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *self) {
  JavaMathBigInteger *max = [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(nil_chk(self->coeffs_), 0))) abs];
  for (jint i = 1; i < ((IOSObjectArray *) nil_chk(self->coeffs_))->size_; i++) {
    JavaMathBigInteger *coeff = [((JavaMathBigInteger *) nil_chk(IOSObjectArray_Get(self->coeffs_, i))) abs];
    if ([((JavaMathBigInteger *) nil_chk(coeff)) compareToWithId:max] > 0) {
      max = coeff;
    }
  }
  return max;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial)