//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/test/Test.java
//

#ifndef Test_H
#define Test_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleUtilTestTestResult;

@protocol LibOrgBouncycastleUtilTestTest < JavaObject >

- (NSString *)getName;

- (id<LibOrgBouncycastleUtilTestTestResult>)perform;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTestTest)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTestTest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Test_H