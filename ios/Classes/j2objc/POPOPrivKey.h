//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/POPOPrivKey.java
//

#ifndef POPOPrivKey_H
#define POPOPrivKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CrmfPKMACValue;
@class LibOrgBouncycastleAsn1CrmfSubsequentMessage;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CrmfPOPOPrivKey : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >
@property (readonly, class) jint thisMessage NS_SWIFT_NAME(thisMessage);
@property (readonly, class) jint subsequentMessage NS_SWIFT_NAME(subsequentMessage);
@property (readonly, class) jint dhMAC NS_SWIFT_NAME(dhMAC);
@property (readonly, class) jint agreeMAC NS_SWIFT_NAME(agreeMAC);
@property (readonly, class) jint encryptedKey NS_SWIFT_NAME(encryptedKey);

+ (jint)thisMessage;

+ (jint)subsequentMessage;

+ (jint)dhMAC;

+ (jint)agreeMAC;

+ (jint)encryptedKey;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfPKMACValue:(LibOrgBouncycastleAsn1CrmfPKMACValue *)agreeMac;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage:(LibOrgBouncycastleAsn1CrmfSubsequentMessage *)msg;

+ (LibOrgBouncycastleAsn1CrmfPOPOPrivKey *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CrmfPOPOPrivKey *)getInstanceWithId:(id)obj;

- (jint)getType;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey)

inline jint LibOrgBouncycastleAsn1CrmfPOPOPrivKey_get_thisMessage(void);
#define LibOrgBouncycastleAsn1CrmfPOPOPrivKey_thisMessage 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, thisMessage, jint)

inline jint LibOrgBouncycastleAsn1CrmfPOPOPrivKey_get_subsequentMessage(void);
#define LibOrgBouncycastleAsn1CrmfPOPOPrivKey_subsequentMessage 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, subsequentMessage, jint)

inline jint LibOrgBouncycastleAsn1CrmfPOPOPrivKey_get_dhMAC(void);
#define LibOrgBouncycastleAsn1CrmfPOPOPrivKey_dhMAC 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, dhMAC, jint)

inline jint LibOrgBouncycastleAsn1CrmfPOPOPrivKey_get_agreeMAC(void);
#define LibOrgBouncycastleAsn1CrmfPOPOPrivKey_agreeMAC 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, agreeMAC, jint)

inline jint LibOrgBouncycastleAsn1CrmfPOPOPrivKey_get_encryptedKey(void);
#define LibOrgBouncycastleAsn1CrmfPOPOPrivKey_encryptedKey 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CrmfPOPOPrivKey, encryptedKey, jint)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *LibOrgBouncycastleAsn1CrmfPOPOPrivKey_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfPKMACValue_(LibOrgBouncycastleAsn1CrmfPKMACValue *agreeMac);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfPOPOPrivKey *self, LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *new_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfPOPOPrivKey *create_LibOrgBouncycastleAsn1CrmfPOPOPrivKey_initWithLibOrgBouncycastleAsn1CrmfSubsequentMessage_(LibOrgBouncycastleAsn1CrmfSubsequentMessage *msg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CrmfPOPOPrivKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // POPOPrivKey_H