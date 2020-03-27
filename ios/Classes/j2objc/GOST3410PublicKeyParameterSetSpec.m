//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/GOST3410PublicKeyParameterSetSpec.java
//

#include "GOST3410PublicKeyParameterSetSpec.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec () {
 @public
  JavaMathBigInteger *p_;
  JavaMathBigInteger *q_;
  JavaMathBigInteger *a_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec, p_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec, a_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)a {
  LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(self, p, q, a);
  return self;
}

- (JavaMathBigInteger *)getP {
  return self->p_;
}

- (JavaMathBigInteger *)getQ {
  return self->q_;
}

- (JavaMathBigInteger *)getA {
  return self->a_;
}

- (jboolean)isEqual:(id)o {
  if ([o isKindOfClass:[LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec class]]) {
    LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *other = (LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *) o;
    return [((JavaMathBigInteger *) nil_chk(self->a_)) isEqual:((LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *) nil_chk(other))->a_] && [((JavaMathBigInteger *) nil_chk(self->p_)) isEqual:other->p_] && [((JavaMathBigInteger *) nil_chk(self->q_)) isEqual:other->q_];
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(a_)) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk(p_)) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk(q_)) hash]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[1].selector = @selector(getP);
  methods[2].selector = @selector(getQ);
  methods[3].selector = @selector(getA);
  methods[4].selector = @selector(isEqual:);
  methods[5].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "q_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "a_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec = { "GOST3410PublicKeyParameterSetSpec", "lib.org.bouncycastle.jce.spec", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec;
}

@end

void LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *self, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) {
  NSObject_init(self);
  self->p_ = p;
  self->q_ = q;
  self->a_ = a;
}

LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *new_LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, p, q, a)
}

LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *create_LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, p, q, a)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec)