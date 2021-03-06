//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ContainedPacket.java
//

#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Packet.h"
#include "java/io/ByteArrayOutputStream.h"

@implementation LibOrgBouncycastleBcpgContainedPacket

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)getEncoded {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writePacketWithLibOrgBouncycastleBcpgContainedPacket:self];
  [pOut close];
  return [bOut toByteArray];
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)pOut {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 0, -1, -1, -1 },
    { NULL, "V", 0x401, 1, 2, 0, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getEncoded);
  methods[2].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoIOException;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgContainedPacket = { "ContainedPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, NULL, 7, 0x401, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgContainedPacket;
}

@end

void LibOrgBouncycastleBcpgContainedPacket_init(LibOrgBouncycastleBcpgContainedPacket *self) {
  LibOrgBouncycastleBcpgPacket_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgContainedPacket)
