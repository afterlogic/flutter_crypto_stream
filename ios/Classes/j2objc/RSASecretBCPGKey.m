//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/RSASecretBCPGKey.java
//

#include "BCPGInputStream.h"
#include "BCPGObject.h"
#include "BCPGOutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "RSASecretBCPGKey.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleBcpgRSASecretBCPGKey

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)d
                    withJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q {
  LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(self, d, p, q);
  return self;
}

- (JavaMathBigInteger *)getModulus {
  return [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(p_)) getValue])) multiplyWithJavaMathBigInteger:[((LibOrgBouncycastleBcpgMPInteger *) nil_chk(q_)) getValue]];
}

- (JavaMathBigInteger *)getPrivateExponent {
  return [((LibOrgBouncycastleBcpgMPInteger *) nil_chk(d_)) getValue];
}

- (JavaMathBigInteger *)getPrimeP {
  return [((LibOrgBouncycastleBcpgMPInteger *) nil_chk(p_)) getValue];
}

- (JavaMathBigInteger *)getPrimeQ {
  return [((LibOrgBouncycastleBcpgMPInteger *) nil_chk(q_)) getValue];
}

- (JavaMathBigInteger *)getPrimeExponentP {
  return expP_;
}

- (JavaMathBigInteger *)getPrimeExponentQ {
  return expQ_;
}

- (JavaMathBigInteger *)getCrtCoefficient {
  return crt_;
}

- (NSString *)getFormat {
  return @"PGP";
}

- (IOSByteArray *)getEncoded {
  @try {
    return [super getEncoded];
  }
  @catch (JavaIoIOException *e) {
    return nil;
  }
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writeObjectWithLibOrgBouncycastleBcpgBCPGObject:d_];
  [outArg writeObjectWithLibOrgBouncycastleBcpgBCPGObject:p_];
  [outArg writeObjectWithLibOrgBouncycastleBcpgBCPGObject:q_];
  [outArg writeObjectWithLibOrgBouncycastleBcpgBCPGObject:u_];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[2].selector = @selector(getModulus);
  methods[3].selector = @selector(getPrivateExponent);
  methods[4].selector = @selector(getPrimeP);
  methods[5].selector = @selector(getPrimeQ);
  methods[6].selector = @selector(getPrimeExponentP);
  methods[7].selector = @selector(getPrimeExponentQ);
  methods[8].selector = @selector(getCrtCoefficient);
  methods[9].selector = @selector(getFormat);
  methods[10].selector = @selector(getEncoded);
  methods[11].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "d_", "LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "p_", "LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "q_", "LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "u_", "LLibOrgBouncycastleBcpgMPInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "expP_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "expQ_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "crt_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgRSASecretBCPGKey = { "RSASecretBCPGKey", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 12, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgRSASecretBCPGKey;
}

@end

void LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgRSASecretBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  self->d_ = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  self->p_ = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  self->q_ = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  self->u_ = new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  self->expP_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->d_)) getValue])) remainderWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->p_)) getValue])) subtractWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)]];
  self->expQ_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->d_)) getValue])) remainderWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->q_)) getValue])) subtractWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)]];
  self->crt_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->q_)) getValue])) modInverseWithJavaMathBigInteger:[((LibOrgBouncycastleBcpgMPInteger *) nil_chk(self->p_)) getValue]];
}

LibOrgBouncycastleBcpgRSASecretBCPGKey *new_LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgRSASecretBCPGKey, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgRSASecretBCPGKey *create_LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgRSASecretBCPGKey, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleBcpgRSASecretBCPGKey *self, JavaMathBigInteger *d, JavaMathBigInteger *p, JavaMathBigInteger *q) {
  LibOrgBouncycastleBcpgBCPGObject_init(self);
  jint cmp = [((JavaMathBigInteger *) nil_chk(p)) compareToWithId:q];
  if (cmp >= 0) {
    if (cmp == 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"p and q cannot be equal");
    }
    JavaMathBigInteger *tmp = p;
    p = q;
    q = tmp;
  }
  self->d_ = new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(d);
  self->p_ = new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(p);
  self->q_ = new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(q);
  self->u_ = new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_([((JavaMathBigInteger *) nil_chk(p)) modInverseWithJavaMathBigInteger:q]);
  self->expP_ = [((JavaMathBigInteger *) nil_chk(d)) remainderWithJavaMathBigInteger:[p subtractWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)]];
  self->expQ_ = [d remainderWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(q)) subtractWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)]];
  self->crt_ = [q modInverseWithJavaMathBigInteger:p];
}

LibOrgBouncycastleBcpgRSASecretBCPGKey *new_LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *d, JavaMathBigInteger *p, JavaMathBigInteger *q) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgRSASecretBCPGKey, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, d, p, q)
}

LibOrgBouncycastleBcpgRSASecretBCPGKey *create_LibOrgBouncycastleBcpgRSASecretBCPGKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *d, JavaMathBigInteger *p, JavaMathBigInteger *q) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgRSASecretBCPGKey, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, d, p, q)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgRSASecretBCPGKey)
