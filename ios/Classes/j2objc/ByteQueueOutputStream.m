//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ByteQueueOutputStream.java
//

#include "ByteQueue.h"
#include "ByteQueueOutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/OutputStream.h"

@interface LibOrgBouncycastleCryptoTlsByteQueueOutputStream () {
 @public
  LibOrgBouncycastleCryptoTlsByteQueue *buffer_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsByteQueueOutputStream, buffer_, LibOrgBouncycastleCryptoTlsByteQueue *)

@implementation LibOrgBouncycastleCryptoTlsByteQueueOutputStream

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsByteQueueOutputStream_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleCryptoTlsByteQueue *)getBuffer {
  return buffer_;
}

- (void)writeWithInt:(jint)b {
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) addDataWithByteArray:[IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) b } count:1] withInt:0 withInt:1];
}

- (void)writeWithByteArray:(IOSByteArray *)b
                   withInt:(jint)off
                   withInt:(jint)len {
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) addDataWithByteArray:b withInt:off withInt:len];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsByteQueue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 3, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getBuffer);
  methods[2].selector = @selector(writeWithInt:);
  methods[3].selector = @selector(writeWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buffer_", "LLibOrgBouncycastleCryptoTlsByteQueue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "write", "I", "LJavaIoIOException;", "[BII" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsByteQueueOutputStream = { "ByteQueueOutputStream", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsByteQueueOutputStream;
}

@end

void LibOrgBouncycastleCryptoTlsByteQueueOutputStream_init(LibOrgBouncycastleCryptoTlsByteQueueOutputStream *self) {
  JavaIoOutputStream_init(self);
  self->buffer_ = new_LibOrgBouncycastleCryptoTlsByteQueue_init();
}

LibOrgBouncycastleCryptoTlsByteQueueOutputStream *new_LibOrgBouncycastleCryptoTlsByteQueueOutputStream_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsByteQueueOutputStream, init)
}

LibOrgBouncycastleCryptoTlsByteQueueOutputStream *create_LibOrgBouncycastleCryptoTlsByteQueueOutputStream_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsByteQueueOutputStream, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsByteQueueOutputStream)
