//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ECLookupTable.java
//

#ifndef ECLookupTable_H
#define ECLookupTable_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleMathEcECPoint;

@protocol LibOrgBouncycastleMathEcECLookupTable < JavaObject >

- (jint)getSize;

- (LibOrgBouncycastleMathEcECPoint *)lookupWithInt:(jint)index;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcECLookupTable)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcECLookupTable)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECLookupTable_H