//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CertificateHolderReference.java
//

#ifndef CertificateHolderReference_H
#define CertificateHolderReference_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleAsn1EacCertificateHolderReference : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)countryCode
                              withNSString:(NSString *)holderMnemonic
                              withNSString:(NSString *)sequenceNumber;

- (NSString *)getCountryCode;

- (IOSByteArray *)getEncoded;

- (NSString *)getHolderMnemonic;

- (NSString *)getSequenceNumber;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)contents;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacCertificateHolderReference)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleAsn1EacCertificateHolderReference *self, NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateHolderReference *new_LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithNSString_withNSString_withNSString_(NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateHolderReference *create_LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithNSString_withNSString_withNSString_(NSString *countryCode, NSString *holderMnemonic, NSString *sequenceNumber);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithByteArray_(LibOrgBouncycastleAsn1EacCertificateHolderReference *self, IOSByteArray *contents);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateHolderReference *new_LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithByteArray_(IOSByteArray *contents) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacCertificateHolderReference *create_LibOrgBouncycastleAsn1EacCertificateHolderReference_initWithByteArray_(IOSByteArray *contents);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacCertificateHolderReference)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertificateHolderReference_H
