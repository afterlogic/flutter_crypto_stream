//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ua/DSTU4145BinaryField.java
//

#ifndef DSTU4145BinaryField_H
#define DSTU4145BinaryField_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1UaDSTU4145BinaryField : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k;

- (instancetype __nonnull)initWithInt:(jint)m
                              withInt:(jint)k1
                              withInt:(jint)k2
                              withInt:(jint)k3;

+ (LibOrgBouncycastleAsn1UaDSTU4145BinaryField *)getInstanceWithId:(id)obj;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1UaDSTU4145BinaryField)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1UaDSTU4145BinaryField *LibOrgBouncycastleAsn1UaDSTU4145BinaryField_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_withInt_withInt_(LibOrgBouncycastleAsn1UaDSTU4145BinaryField *self, jint m, jint k1, jint k2, jint k3);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1UaDSTU4145BinaryField *new_LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_withInt_withInt_(jint m, jint k1, jint k2, jint k3) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1UaDSTU4145BinaryField *create_LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_withInt_withInt_(jint m, jint k1, jint k2, jint k3);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_(LibOrgBouncycastleAsn1UaDSTU4145BinaryField *self, jint m, jint k);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1UaDSTU4145BinaryField *new_LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_(jint m, jint k) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1UaDSTU4145BinaryField *create_LibOrgBouncycastleAsn1UaDSTU4145BinaryField_initWithInt_withInt_(jint m, jint k);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1UaDSTU4145BinaryField)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DSTU4145BinaryField_H
