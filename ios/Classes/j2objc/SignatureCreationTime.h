//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/SignatureCreationTime.java
//

#ifndef SignatureCreationTime_H
#define SignatureCreationTime_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SignatureSubpacket.h"

@class IOSByteArray;
@class JavaUtilDate;

@interface LibOrgBouncycastleBcpgSigSignatureCreationTime : LibOrgBouncycastleBcpgSignatureSubpacket

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                              withBoolean:(jboolean)isLongLength
                            withByteArray:(IOSByteArray *)data;

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                         withJavaUtilDate:(JavaUtilDate *)date;

- (JavaUtilDate *)getTime;

#pragma mark Protected

+ (IOSByteArray *)timeToBytesWithJavaUtilDate:(JavaUtilDate *)date;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                          withBoolean:(jboolean)arg1
                          withBoolean:(jboolean)arg2
                        withByteArray:(IOSByteArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSigSignatureCreationTime)

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleBcpgSigSignatureCreationTime_timeToBytesWithJavaUtilDate_(JavaUtilDate *date);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigSignatureCreationTime *self, jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureCreationTime *new_LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureCreationTime *create_LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withJavaUtilDate_(LibOrgBouncycastleBcpgSigSignatureCreationTime *self, jboolean critical, JavaUtilDate *date);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureCreationTime *new_LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withJavaUtilDate_(jboolean critical, JavaUtilDate *date) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigSignatureCreationTime *create_LibOrgBouncycastleBcpgSigSignatureCreationTime_initWithBoolean_withJavaUtilDate_(jboolean critical, JavaUtilDate *date);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSigSignatureCreationTime)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignatureCreationTime_H
