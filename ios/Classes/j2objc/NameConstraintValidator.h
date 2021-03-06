//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/NameConstraintValidator.java
//

#ifndef NameConstraintValidator_H
#define NameConstraintValidator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1X509GeneralName;
@class LibOrgBouncycastleAsn1X509GeneralSubtree;

@protocol LibOrgBouncycastleAsn1X509NameConstraintValidator < JavaObject >

- (void)checkPermittedWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)name;

- (void)checkExcludedWithLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)name;

- (void)intersectPermittedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtree:(LibOrgBouncycastleAsn1X509GeneralSubtree *)permitted;

- (void)intersectPermittedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtreeArray:(IOSObjectArray *)permitted;

- (void)intersectEmptyPermittedSubtreeWithInt:(jint)nameType;

- (void)addExcludedSubtreeWithLibOrgBouncycastleAsn1X509GeneralSubtree:(LibOrgBouncycastleAsn1X509GeneralSubtree *)subtree;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509NameConstraintValidator)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509NameConstraintValidator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NameConstraintValidator_H
