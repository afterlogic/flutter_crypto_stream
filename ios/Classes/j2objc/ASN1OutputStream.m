//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1OutputStream.java
//

#include "ASN1Encodable.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "BERTags.h"
#include "DEROutputStream.h"
#include "DLOutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/io/OutputStream.h"

@interface LibOrgBouncycastleAsn1ASN1OutputStream () {
 @public
  JavaIoOutputStream *os_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1OutputStream, os_, JavaIoOutputStream *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1ASN1OutputStream_writeWithInt_(LibOrgBouncycastleAsn1ASN1OutputStream *self, jint b);

@interface LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream : LibOrgBouncycastleAsn1ASN1OutputStream {
 @public
  jboolean first_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outer$
                                        withJavaIoOutputStream:(JavaIoOutputStream *)os;

- (void)writeWithInt:(jint)b;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream)

__attribute__((unused)) static void LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *self, LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *new_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *create_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream)

@implementation LibOrgBouncycastleAsn1ASN1OutputStream

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)os {
  LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(self, os);
  return self;
}

- (void)writeLengthWithInt:(jint)length {
  if (length > 127) {
    jint size = 1;
    jint val = length;
    while ((JreURShiftAssignInt(&val, 8)) != 0) {
      size++;
    }
    [self writeWithInt:(jbyte) (size | (jint) 0x80)];
    for (jint i = (size - 1) * 8; i >= 0; i -= 8) {
      [self writeWithInt:(jbyte) (JreRShift32(length, i))];
    }
  }
  else {
    [self writeWithInt:(jbyte) length];
  }
}

- (void)writeWithInt:(jint)b {
  LibOrgBouncycastleAsn1ASN1OutputStream_writeWithInt_(self, b);
}

- (void)writeWithByteArray:(IOSByteArray *)bytes {
  [((JavaIoOutputStream *) nil_chk(os_)) writeWithByteArray:bytes];
}

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len {
  [((JavaIoOutputStream *) nil_chk(os_)) writeWithByteArray:bytes withInt:off withInt:len];
}

- (void)writeEncodedWithInt:(jint)tag
              withByteArray:(IOSByteArray *)bytes {
  [self writeWithInt:tag];
  [self writeLengthWithInt:((IOSByteArray *) nil_chk(bytes))->size_];
  [self writeWithByteArray:bytes];
}

- (void)writeTagWithInt:(jint)flags
                withInt:(jint)tagNo {
  if (tagNo < 31) {
    [self writeWithInt:flags | tagNo];
  }
  else {
    [self writeWithInt:flags | (jint) 0x1f];
    if (tagNo < 128) {
      [self writeWithInt:tagNo];
    }
    else {
      IOSByteArray *stack = [IOSByteArray newArrayWithLength:5];
      jint pos = stack->size_;
      *IOSByteArray_GetRef(stack, --pos) = (jbyte) (tagNo & (jint) 0x7F);
      do {
        JreRShiftAssignInt(&tagNo, 7);
        *IOSByteArray_GetRef(stack, --pos) = (jbyte) ((tagNo & (jint) 0x7F) | (jint) 0x80);
      }
      while (tagNo > 127);
      [self writeWithByteArray:stack withInt:pos withInt:stack->size_ - pos];
    }
  }
}

- (void)writeEncodedWithInt:(jint)flags
                    withInt:(jint)tagNo
              withByteArray:(IOSByteArray *)bytes {
  [self writeTagWithInt:flags withInt:tagNo];
  [self writeLengthWithInt:((IOSByteArray *) nil_chk(bytes))->size_];
  [self writeWithByteArray:bytes];
}

- (void)writeNull {
  [((JavaIoOutputStream *) nil_chk(os_)) writeWithInt:LibOrgBouncycastleAsn1BERTags_NULL];
  [((JavaIoOutputStream *) nil_chk(os_)) writeWithInt:(jint) 0x00];
}

- (void)writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([obj toASN1Primitive])) encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:self];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"null object detected");
  }
}

- (void)writeImplicitObjectWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)obj {
  if (obj != nil) {
    [obj encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:new_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(self, os_)];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(@"null object detected");
  }
}

- (void)close {
  [((JavaIoOutputStream *) nil_chk(os_)) close];
}

- (void)flush {
  [((JavaIoOutputStream *) nil_chk(os_)) flush];
}

- (LibOrgBouncycastleAsn1ASN1OutputStream *)getDERSubStream {
  return new_LibOrgBouncycastleAsn1DEROutputStream_initWithJavaIoOutputStream_(os_);
}

- (LibOrgBouncycastleAsn1ASN1OutputStream *)getDLSubStream {
  return new_LibOrgBouncycastleAsn1DLOutputStream_initWithJavaIoOutputStream_(os_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 5, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 6, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 7, 8, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 9, 10, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 7, 11, 3, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 13, 3, -1, -1, -1 },
    { NULL, "V", 0x0, 14, 15, 3, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OutputStream;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OutputStream;", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:);
  methods[1].selector = @selector(writeLengthWithInt:);
  methods[2].selector = @selector(writeWithInt:);
  methods[3].selector = @selector(writeWithByteArray:);
  methods[4].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(writeEncodedWithInt:withByteArray:);
  methods[6].selector = @selector(writeTagWithInt:withInt:);
  methods[7].selector = @selector(writeEncodedWithInt:withInt:withByteArray:);
  methods[8].selector = @selector(writeNull);
  methods[9].selector = @selector(writeObjectWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[10].selector = @selector(writeImplicitObjectWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[11].selector = @selector(close);
  methods[12].selector = @selector(flush);
  methods[13].selector = @selector(getDERSubStream);
  methods[14].selector = @selector(getDLSubStream);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "os_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoOutputStream;", "writeLength", "I", "LJavaIoIOException;", "write", "[B", "[BII", "writeEncoded", "I[B", "writeTag", "II", "II[B", "writeObject", "LLibOrgBouncycastleAsn1ASN1Encodable;", "writeImplicitObject", "LLibOrgBouncycastleAsn1ASN1Primitive;", "LLibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1OutputStream = { "ASN1OutputStream", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 15, 1, -1, 16, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1OutputStream;
}

@end

void LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream *self, JavaIoOutputStream *os) {
  NSObject_init(self);
  self->os_ = os;
}

LibOrgBouncycastleAsn1ASN1OutputStream *new_LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1OutputStream, initWithJavaIoOutputStream_, os)
}

LibOrgBouncycastleAsn1ASN1OutputStream *create_LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(JavaIoOutputStream *os) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1OutputStream, initWithJavaIoOutputStream_, os)
}

void LibOrgBouncycastleAsn1ASN1OutputStream_writeWithInt_(LibOrgBouncycastleAsn1ASN1OutputStream *self, jint b) {
  [((JavaIoOutputStream *) nil_chk(self->os_)) writeWithInt:b];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1OutputStream)

@implementation LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outer$
                                        withJavaIoOutputStream:(JavaIoOutputStream *)os {
  LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(self, outer$, os);
  return self;
}

- (void)writeWithInt:(jint)b {
  if (first_) {
    first_ = false;
  }
  else {
    LibOrgBouncycastleAsn1ASN1OutputStream_writeWithInt_(self, b);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1OutputStream:withJavaIoOutputStream:);
  methods[1].selector = @selector(writeWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "first_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoOutputStream;", "write", "I", "LJavaIoIOException;", "LLibOrgBouncycastleAsn1ASN1OutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream = { "ImplicitOutputStream", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x2, 2, 1, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream;
}

@end

void LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *self, LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os) {
  LibOrgBouncycastleAsn1ASN1OutputStream_initWithJavaIoOutputStream_(self, os);
  self->first_ = true;
}

LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *new_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream, initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_, outer$, os)
}

LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream *create_LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream_initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_(LibOrgBouncycastleAsn1ASN1OutputStream *outer$, JavaIoOutputStream *os) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream, initWithLibOrgBouncycastleAsn1ASN1OutputStream_withJavaIoOutputStream_, outer$, os)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1OutputStream_ImplicitOutputStream)
