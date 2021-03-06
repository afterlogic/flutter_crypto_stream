//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/X509Principal.java
//

#ifndef X509Principal_H
#define X509Principal_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "X509Name.h"
#include "java/security/Principal.h"

@class IOSByteArray;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509X509NameEntryConverter;

@interface LibOrgBouncycastleJceX509Principal : LibOrgBouncycastleAsn1X509X509Name < JavaSecurityPrincipal >

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)reverse
                    withJavaUtilHashtable:(JavaUtilHashtable *)lookUp
                             withNSString:(NSString *)dirName;

- (instancetype __nonnull)initWithBoolean:(jboolean)reverse
                             withNSString:(NSString *)dirName;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)bytes;

- (instancetype __nonnull)initWithJavaUtilHashtable:(JavaUtilHashtable *)attributes;

- (instancetype __nonnull)initWithNSString:(NSString *)dirName;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)ordering
                           withJavaUtilHashtable:(JavaUtilHashtable *)attributes;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)oids
                              withJavaUtilVector:(JavaUtilVector *)values;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)name;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)name;

- (IOSByteArray *)getEncoded;

- (NSString *)getName;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                    withJavaUtilHashtable:(JavaUtilHashtable *)arg1
                             withNSString:(NSString *)arg2
withLibOrgBouncycastleAsn1X509X509NameEntryConverter:(LibOrgBouncycastleAsn1X509X509NameEntryConverter *)arg3 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
                             withNSString:(NSString *)arg1
withLibOrgBouncycastleAsn1X509X509NameEntryConverter:(LibOrgBouncycastleAsn1X509X509NameEntryConverter *)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)arg0
                           withJavaUtilHashtable:(JavaUtilHashtable *)arg1
withLibOrgBouncycastleAsn1X509X509NameEntryConverter:(LibOrgBouncycastleAsn1X509X509NameEntryConverter *)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaUtilVector:(JavaUtilVector *)arg0
                              withJavaUtilVector:(JavaUtilVector *)arg1
withLibOrgBouncycastleAsn1X509X509NameEntryConverter:(LibOrgBouncycastleAsn1X509X509NameEntryConverter *)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
withLibOrgBouncycastleAsn1X509X509NameEntryConverter:(LibOrgBouncycastleAsn1X509X509NameEntryConverter *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceX509Principal)

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithByteArray_(LibOrgBouncycastleJceX509Principal *self, IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithByteArray_(IOSByteArray *bytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X509X509Name_(LibOrgBouncycastleJceX509Principal *self, LibOrgBouncycastleAsn1X509X509Name *name);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X509X509Name_(LibOrgBouncycastleAsn1X509X509Name *name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X509X509Name_(LibOrgBouncycastleAsn1X509X509Name *name);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleJceX509Principal *self, LibOrgBouncycastleAsn1X500X500Name *name);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X500X500Name *name) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithLibOrgBouncycastleAsn1X500X500Name_(LibOrgBouncycastleAsn1X500X500Name *name);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithJavaUtilHashtable_(LibOrgBouncycastleJceX509Principal *self, JavaUtilHashtable *attributes);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithJavaUtilHashtable_(JavaUtilHashtable *attributes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithJavaUtilHashtable_(JavaUtilHashtable *attributes);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilHashtable_(LibOrgBouncycastleJceX509Principal *self, JavaUtilVector *ordering, JavaUtilHashtable *attributes);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *attributes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilHashtable_(JavaUtilVector *ordering, JavaUtilHashtable *attributes);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilVector_(LibOrgBouncycastleJceX509Principal *self, JavaUtilVector *oids, JavaUtilVector *values);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *oids, JavaUtilVector *values) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithJavaUtilVector_withJavaUtilVector_(JavaUtilVector *oids, JavaUtilVector *values);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithNSString_(LibOrgBouncycastleJceX509Principal *self, NSString *dirName);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithNSString_(NSString *dirName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithNSString_(NSString *dirName);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithBoolean_withNSString_(LibOrgBouncycastleJceX509Principal *self, jboolean reverse, NSString *dirName);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithBoolean_withNSString_(jboolean reverse, NSString *dirName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithBoolean_withNSString_(jboolean reverse, NSString *dirName);

FOUNDATION_EXPORT void LibOrgBouncycastleJceX509Principal_initWithBoolean_withJavaUtilHashtable_withNSString_(LibOrgBouncycastleJceX509Principal *self, jboolean reverse, JavaUtilHashtable *lookUp, NSString *dirName);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *new_LibOrgBouncycastleJceX509Principal_initWithBoolean_withJavaUtilHashtable_withNSString_(jboolean reverse, JavaUtilHashtable *lookUp, NSString *dirName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *create_LibOrgBouncycastleJceX509Principal_initWithBoolean_withJavaUtilHashtable_withNSString_(jboolean reverse, JavaUtilHashtable *lookUp, NSString *dirName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceX509Principal)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509Principal_H
