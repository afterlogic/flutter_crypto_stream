//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/CRC24.java
//

#ifndef CRC24_H
#define CRC24_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleBcpgCRC24 : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (jint)getValue;

- (void)reset;

- (void)updateWithInt:(jint)b;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgCRC24)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgCRC24_init(LibOrgBouncycastleBcpgCRC24 *self);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgCRC24 *new_LibOrgBouncycastleBcpgCRC24_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgCRC24 *create_LibOrgBouncycastleBcpgCRC24_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgCRC24)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CRC24_H