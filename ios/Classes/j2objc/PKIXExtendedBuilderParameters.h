//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PKIXExtendedBuilderParameters.java
//

#ifndef PKIXExtendedBuilderParameters_H
#define PKIXExtendedBuilderParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/CertPathParameters.h"

@class JavaSecurityCertPKIXBuilderParameters;
@class LibOrgBouncycastleJcajcePKIXExtendedParameters;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters : NSObject < JavaSecurityCertCertPathParameters >

#pragma mark Public

- (id)java_clone;

- (LibOrgBouncycastleJcajcePKIXExtendedParameters *)getBaseParameters;

- (id<JavaUtilSet>)getExcludedCerts;

- (jint)getMaxPathLength;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters)

@interface LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithJavaSecurityCertPKIXBuilderParameters:(JavaSecurityCertPKIXBuilderParameters *)baseParameters;

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajcePKIXExtendedParameters:(LibOrgBouncycastleJcajcePKIXExtendedParameters *)baseParameters;

- (LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *)addExcludedCertsWithJavaUtilSet:(id<JavaUtilSet>)excludedCerts;

- (LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters *)build;

- (LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *)setMaxPathLengthWithInt:(jint)maxPathLength;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithJavaSecurityCertPKIXBuilderParameters_(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *self, JavaSecurityCertPKIXBuilderParameters *baseParameters);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *new_LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithJavaSecurityCertPKIXBuilderParameters_(JavaSecurityCertPKIXBuilderParameters *baseParameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *create_LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithJavaSecurityCertPKIXBuilderParameters_(JavaSecurityCertPKIXBuilderParameters *baseParameters);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithLibOrgBouncycastleJcajcePKIXExtendedParameters_(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *self, LibOrgBouncycastleJcajcePKIXExtendedParameters *baseParameters);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *new_LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithLibOrgBouncycastleJcajcePKIXExtendedParameters_(LibOrgBouncycastleJcajcePKIXExtendedParameters *baseParameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder *create_LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder_initWithLibOrgBouncycastleJcajcePKIXExtendedParameters_(LibOrgBouncycastleJcajcePKIXExtendedParameters *baseParameters);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajcePKIXExtendedBuilderParameters_Builder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIXExtendedBuilderParameters_H
