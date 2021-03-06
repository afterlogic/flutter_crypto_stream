//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ByteQueueInputStream.java
//

#include "ByteQueue.h"
#include "ByteQueueInputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "java/lang/Math.h"

@interface LibOrgBouncycastleCryptoTlsByteQueueInputStream () {
 @public
  LibOrgBouncycastleCryptoTlsByteQueue *buffer_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsByteQueueInputStream, buffer_, LibOrgBouncycastleCryptoTlsByteQueue *)

@implementation LibOrgBouncycastleCryptoTlsByteQueueInputStream

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoTlsByteQueueInputStream_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)addBytesWithByteArray:(IOSByteArray *)bytes {
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) addDataWithByteArray:bytes withInt:0 withInt:((IOSByteArray *) nil_chk(bytes))->size_];
}

- (jint)peekWithByteArray:(IOSByteArray *)buf {
  jint bytesToRead = JavaLangMath_minWithInt_withInt_([((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) available], ((IOSByteArray *) nil_chk(buf))->size_);
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) readWithByteArray:buf withInt:0 withInt:bytesToRead withInt:0];
  return bytesToRead;
}

- (jint)read {
  if ([((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) available] == 0) {
    return -1;
  }
  return IOSByteArray_Get(nil_chk([((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) removeDataWithInt:1 withInt:0]), 0) & (jint) 0xFF;
}

- (jint)readWithByteArray:(IOSByteArray *)b {
  return [self readWithByteArray:b withInt:0 withInt:((IOSByteArray *) nil_chk(b))->size_];
}

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len {
  jint bytesToRead = JavaLangMath_minWithInt_withInt_([((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) available], len);
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) removeDataWithByteArray:b withInt:off withInt:bytesToRead withInt:0];
  return bytesToRead;
}

- (jlong)skipWithLong:(jlong)n {
  jint bytesToRemove = JavaLangMath_minWithInt_withInt_((jint) n, [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) available]);
  [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) removeDataWithInt:bytesToRemove];
  return bytesToRemove;
}

- (jint)available {
  return [((LibOrgBouncycastleCryptoTlsByteQueue *) nil_chk(buffer_)) available];
}

- (void)close {
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "J", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addBytesWithByteArray:);
  methods[2].selector = @selector(peekWithByteArray:);
  methods[3].selector = @selector(read);
  methods[4].selector = @selector(readWithByteArray:);
  methods[5].selector = @selector(readWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(skipWithLong:);
  methods[7].selector = @selector(available);
  methods[8].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buffer_", "LLibOrgBouncycastleCryptoTlsByteQueue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "addBytes", "[B", "peek", "read", "[BII", "skip", "J" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsByteQueueInputStream = { "ByteQueueInputStream", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 9, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsByteQueueInputStream;
}

@end

void LibOrgBouncycastleCryptoTlsByteQueueInputStream_init(LibOrgBouncycastleCryptoTlsByteQueueInputStream *self) {
  JavaIoInputStream_init(self);
  self->buffer_ = new_LibOrgBouncycastleCryptoTlsByteQueue_init();
}

LibOrgBouncycastleCryptoTlsByteQueueInputStream *new_LibOrgBouncycastleCryptoTlsByteQueueInputStream_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsByteQueueInputStream, init)
}

LibOrgBouncycastleCryptoTlsByteQueueInputStream *create_LibOrgBouncycastleCryptoTlsByteQueueInputStream_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsByteQueueInputStream, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsByteQueueInputStream)
