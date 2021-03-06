//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/ECKeySpec.java
//

#ifndef ECKeySpec_H
#define ECKeySpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/spec/KeySpec.h"

@class LibOrgBouncycastleJceSpecECParameterSpec;

@interface LibOrgBouncycastleJceSpecECKeySpec : NSObject < JavaSecuritySpecKeySpec >

#pragma mark Public

- (LibOrgBouncycastleJceSpecECParameterSpec *)getParams;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleJceSpecECParameterSpec:(LibOrgBouncycastleJceSpecECParameterSpec *)spec;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecECKeySpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecECKeySpec_initWithLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJceSpecECKeySpec *self, LibOrgBouncycastleJceSpecECParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECKeySpec *new_LibOrgBouncycastleJceSpecECKeySpec_initWithLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJceSpecECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecECKeySpec *create_LibOrgBouncycastleJceSpecECKeySpec_initWithLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJceSpecECParameterSpec *spec);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecECKeySpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECKeySpec_H
