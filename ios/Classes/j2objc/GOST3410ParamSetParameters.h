//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptopro/GOST3410ParamSetParameters.java
//

#ifndef GOST3410ParamSetParameters_H
#define GOST3410ParamSetParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters : LibOrgBouncycastleAsn1ASN1Object {
 @public
  jint keySize_;
  LibOrgBouncycastleAsn1ASN1Integer *p_;
  LibOrgBouncycastleAsn1ASN1Integer *q_;
  LibOrgBouncycastleAsn1ASN1Integer *a_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (instancetype __nonnull)initWithInt:(jint)keySize
               withJavaMathBigInteger:(JavaMathBigInteger *)p
               withJavaMathBigInteger:(JavaMathBigInteger *)q
               withJavaMathBigInteger:(JavaMathBigInteger *)a;

- (JavaMathBigInteger *)getA;

+ (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                         withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *)getInstanceWithId:(id)obj;

- (jint)getKeySize;

- (jint)getLKeySize;

- (JavaMathBigInteger *)getP;

- (JavaMathBigInteger *)getQ;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters, p_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters, q_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters, a_, LibOrgBouncycastleAsn1ASN1Integer *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *self, jint keySize, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *new_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint keySize, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *create_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(jint keySize, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *a);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *new_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters *create_LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CryptoproGOST3410ParamSetParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410ParamSetParameters_H
