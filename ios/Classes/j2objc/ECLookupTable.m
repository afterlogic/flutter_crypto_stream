//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ECLookupTable.java
//

#include "ECLookupTable.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleMathEcECLookupTable : NSObject

@end

@implementation LibOrgBouncycastleMathEcECLookupTable

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x401, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getSize);
  methods[1].selector = @selector(lookupWithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "lookup", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcECLookupTable = { "ECLookupTable", "lib.org.bouncycastle.math.ec", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcECLookupTable;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcECLookupTable)
