//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/field/GenericPolynomialExtensionField.java
//

#ifndef GenericPolynomialExtensionField_H
#define GenericPolynomialExtensionField_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PolynomialExtensionField.h"

@class JavaMathBigInteger;
@protocol LibOrgBouncycastleMathFieldFiniteField;
@protocol LibOrgBouncycastleMathFieldPolynomial;

@interface LibOrgBouncycastleMathFieldGenericPolynomialExtensionField : NSObject < LibOrgBouncycastleMathFieldPolynomialExtensionField > {
 @public
  id<LibOrgBouncycastleMathFieldFiniteField> subfield_;
  id<LibOrgBouncycastleMathFieldPolynomial> minimalPolynomial_;
}

#pragma mark Public

- (jboolean)isEqual:(id)obj;

- (JavaMathBigInteger *)getCharacteristic;

- (jint)getDegree;

- (jint)getDimension;

- (id<LibOrgBouncycastleMathFieldPolynomial>)getMinimalPolynomial;

- (id<LibOrgBouncycastleMathFieldFiniteField>)getSubfield;

- (NSUInteger)hash;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleMathFieldFiniteField:(id<LibOrgBouncycastleMathFieldFiniteField>)subfield
                               withLibOrgBouncycastleMathFieldPolynomial:(id<LibOrgBouncycastleMathFieldPolynomial>)polynomial;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathFieldGenericPolynomialExtensionField)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathFieldGenericPolynomialExtensionField, subfield_, id<LibOrgBouncycastleMathFieldFiniteField>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathFieldGenericPolynomialExtensionField, minimalPolynomial_, id<LibOrgBouncycastleMathFieldPolynomial>)

FOUNDATION_EXPORT void LibOrgBouncycastleMathFieldGenericPolynomialExtensionField_initWithLibOrgBouncycastleMathFieldFiniteField_withLibOrgBouncycastleMathFieldPolynomial_(LibOrgBouncycastleMathFieldGenericPolynomialExtensionField *self, id<LibOrgBouncycastleMathFieldFiniteField> subfield, id<LibOrgBouncycastleMathFieldPolynomial> polynomial);

FOUNDATION_EXPORT LibOrgBouncycastleMathFieldGenericPolynomialExtensionField *new_LibOrgBouncycastleMathFieldGenericPolynomialExtensionField_initWithLibOrgBouncycastleMathFieldFiniteField_withLibOrgBouncycastleMathFieldPolynomial_(id<LibOrgBouncycastleMathFieldFiniteField> subfield, id<LibOrgBouncycastleMathFieldPolynomial> polynomial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathFieldGenericPolynomialExtensionField *create_LibOrgBouncycastleMathFieldGenericPolynomialExtensionField_initWithLibOrgBouncycastleMathFieldFiniteField_withLibOrgBouncycastleMathFieldPolynomial_(id<LibOrgBouncycastleMathFieldFiniteField> subfield, id<LibOrgBouncycastleMathFieldPolynomial> polynomial);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathFieldGenericPolynomialExtensionField)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GenericPolynomialExtensionField_H
