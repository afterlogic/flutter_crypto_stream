//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/NotationData.java
//

#ifndef NotationData_H
#define NotationData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SignatureSubpacket.h"

@class IOSByteArray;

@interface LibOrgBouncycastleBcpgSigNotationData : LibOrgBouncycastleBcpgSignatureSubpacket
@property (readonly, class) jint HEADER_FLAG_LENGTH NS_SWIFT_NAME(HEADER_FLAG_LENGTH);
@property (readonly, class) jint HEADER_NAME_LENGTH NS_SWIFT_NAME(HEADER_NAME_LENGTH);
@property (readonly, class) jint HEADER_VALUE_LENGTH NS_SWIFT_NAME(HEADER_VALUE_LENGTH);

+ (jint)HEADER_FLAG_LENGTH;

+ (jint)HEADER_NAME_LENGTH;

+ (jint)HEADER_VALUE_LENGTH;

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                              withBoolean:(jboolean)isLongLength
                            withByteArray:(IOSByteArray *)data;

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                              withBoolean:(jboolean)humanReadable
                             withNSString:(NSString *)notationName
                             withNSString:(NSString *)notationValue;

- (NSString *)getNotationName;

- (NSString *)getNotationValue;

- (IOSByteArray *)getNotationValueBytes;

- (jboolean)isHumanReadable;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                          withBoolean:(jboolean)arg1
                          withBoolean:(jboolean)arg2
                        withByteArray:(IOSByteArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSigNotationData)

inline jint LibOrgBouncycastleBcpgSigNotationData_get_HEADER_FLAG_LENGTH(void);
#define LibOrgBouncycastleBcpgSigNotationData_HEADER_FLAG_LENGTH 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigNotationData, HEADER_FLAG_LENGTH, jint)

inline jint LibOrgBouncycastleBcpgSigNotationData_get_HEADER_NAME_LENGTH(void);
#define LibOrgBouncycastleBcpgSigNotationData_HEADER_NAME_LENGTH 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigNotationData, HEADER_NAME_LENGTH, jint)

inline jint LibOrgBouncycastleBcpgSigNotationData_get_HEADER_VALUE_LENGTH(void);
#define LibOrgBouncycastleBcpgSigNotationData_HEADER_VALUE_LENGTH 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigNotationData, HEADER_VALUE_LENGTH, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigNotationData *self, jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigNotationData *new_LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigNotationData *create_LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withNSString_withNSString_(LibOrgBouncycastleBcpgSigNotationData *self, jboolean critical, jboolean humanReadable, NSString *notationName, NSString *notationValue);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigNotationData *new_LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withNSString_withNSString_(jboolean critical, jboolean humanReadable, NSString *notationName, NSString *notationValue) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigNotationData *create_LibOrgBouncycastleBcpgSigNotationData_initWithBoolean_withBoolean_withNSString_withNSString_(jboolean critical, jboolean humanReadable, NSString *notationName, NSString *notationValue);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSigNotationData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NotationData_H
