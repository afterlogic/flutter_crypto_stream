//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1Generator.java
//

#ifndef ASN1Generator_H
#define ASN1Generator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoOutputStream;

@interface LibOrgBouncycastleAsn1ASN1Generator : NSObject {
 @public
  JavaIoOutputStream *_out_;
}

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (JavaIoOutputStream *)getRawOutputStream;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1Generator)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1Generator, _out_, JavaIoOutputStream *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1Generator_initWithJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1Generator *self, JavaIoOutputStream *outArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1Generator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1Generator_H