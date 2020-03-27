//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DTLSReassembler.java
//

#include "DTLSReassembler.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleCryptoTlsDTLSReassembler () {
 @public
  jshort msg_type_;
  IOSByteArray *body_;
  JavaUtilVector *missing_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSReassembler, body_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSReassembler, missing_, JavaUtilVector *)

@interface LibOrgBouncycastleCryptoTlsDTLSReassembler_Range : NSObject {
 @public
  jint start_;
  jint end_;
}

- (instancetype)initWithInt:(jint)start
                    withInt:(jint)end;

- (jint)getStart;

- (void)setStartWithInt:(jint)start;

- (jint)getEnd;

- (void)setEndWithInt:(jint)end;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range)

__attribute__((unused)) static void LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *self, jint start, jint end);

__attribute__((unused)) static LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *new_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(jint start, jint end) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *create_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(jint start, jint end);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range)

@implementation LibOrgBouncycastleCryptoTlsDTLSReassembler

- (instancetype)initWithShort:(jshort)msg_type
                      withInt:(jint)length {
  LibOrgBouncycastleCryptoTlsDTLSReassembler_initWithShort_withInt_(self, msg_type, length);
  return self;
}

- (jshort)getMsgType {
  return msg_type_;
}

- (IOSByteArray *)getBodyIfComplete {
  return [((JavaUtilVector *) nil_chk(missing_)) isEmpty] ? body_ : nil;
}

- (void)contributeFragmentWithShort:(jshort)msg_type
                            withInt:(jint)length
                      withByteArray:(IOSByteArray *)buf
                            withInt:(jint)off
                            withInt:(jint)fragment_offset
                            withInt:(jint)fragment_length {
  jint fragment_end = fragment_offset + fragment_length;
  if (self->msg_type_ != msg_type || ((IOSByteArray *) nil_chk(self->body_))->size_ != length || fragment_end > length) {
    return;
  }
  if (fragment_length == 0) {
    if (fragment_offset == 0 && ![((JavaUtilVector *) nil_chk(missing_)) isEmpty]) {
      LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *firstRange = (LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *) cast_chk([((JavaUtilVector *) nil_chk(missing_)) firstElement], [LibOrgBouncycastleCryptoTlsDTLSReassembler_Range class]);
      if ([((LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *) nil_chk(firstRange)) getEnd] == 0) {
        [((JavaUtilVector *) nil_chk(missing_)) removeElementAtWithInt:0];
      }
    }
    return;
  }
  for (jint i = 0; i < [((JavaUtilVector *) nil_chk(missing_)) size]; ++i) {
    LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *range = (LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *) cast_chk([((JavaUtilVector *) nil_chk(missing_)) elementAtWithInt:i], [LibOrgBouncycastleCryptoTlsDTLSReassembler_Range class]);
    if ([((LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *) nil_chk(range)) getStart] >= fragment_end) {
      break;
    }
    if ([range getEnd] > fragment_offset) {
      jint copyStart = JavaLangMath_maxWithInt_withInt_([range getStart], fragment_offset);
      jint copyEnd = JavaLangMath_minWithInt_withInt_([range getEnd], fragment_end);
      jint copyLength = copyEnd - copyStart;
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off + copyStart - fragment_offset, body_, copyStart, copyLength);
      if (copyStart == [range getStart]) {
        if (copyEnd == [range getEnd]) {
          [((JavaUtilVector *) nil_chk(missing_)) removeElementAtWithInt:i--];
        }
        else {
          [range setStartWithInt:copyEnd];
        }
      }
      else {
        if (copyEnd != [range getEnd]) {
          [((JavaUtilVector *) nil_chk(missing_)) insertElementAtWithId:new_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(copyEnd, [range getEnd]) withInt:++i];
        }
        [range setEndWithInt:copyStart];
      }
    }
  }
}

- (void)reset {
  [((JavaUtilVector *) nil_chk(self->missing_)) removeAllElements];
  [((JavaUtilVector *) nil_chk(self->missing_)) addElementWithId:new_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(0, ((IOSByteArray *) nil_chk(body_))->size_)];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "S", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShort:withInt:);
  methods[1].selector = @selector(getMsgType);
  methods[2].selector = @selector(getBodyIfComplete);
  methods[3].selector = @selector(contributeFragmentWithShort:withInt:withByteArray:withInt:withInt:withInt:);
  methods[4].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "msg_type_", "S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "body_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "missing_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "SI", "contributeFragment", "SI[BIII", "LLibOrgBouncycastleCryptoTlsDTLSReassembler_Range;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDTLSReassembler = { "DTLSReassembler", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x0, 5, 3, -1, 3, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDTLSReassembler;
}

@end

void LibOrgBouncycastleCryptoTlsDTLSReassembler_initWithShort_withInt_(LibOrgBouncycastleCryptoTlsDTLSReassembler *self, jshort msg_type, jint length) {
  NSObject_init(self);
  self->missing_ = new_JavaUtilVector_init();
  self->msg_type_ = msg_type;
  self->body_ = [IOSByteArray newArrayWithLength:length];
  [self->missing_ addElementWithId:new_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(0, length)];
}

LibOrgBouncycastleCryptoTlsDTLSReassembler *new_LibOrgBouncycastleCryptoTlsDTLSReassembler_initWithShort_withInt_(jshort msg_type, jint length) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDTLSReassembler, initWithShort_withInt_, msg_type, length)
}

LibOrgBouncycastleCryptoTlsDTLSReassembler *create_LibOrgBouncycastleCryptoTlsDTLSReassembler_initWithShort_withInt_(jshort msg_type, jint length) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDTLSReassembler, initWithShort_withInt_, msg_type, length)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDTLSReassembler)

@implementation LibOrgBouncycastleCryptoTlsDTLSReassembler_Range

- (instancetype)initWithInt:(jint)start
                    withInt:(jint)end {
  LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(self, start, end);
  return self;
}

- (jint)getStart {
  return start_;
}

- (void)setStartWithInt:(jint)start {
  self->start_ = start;
}

- (jint)getEnd {
  return end_;
}

- (void)setEndWithInt:(jint)end {
  self->end_ = end;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:);
  methods[1].selector = @selector(getStart);
  methods[2].selector = @selector(setStartWithInt:);
  methods[3].selector = @selector(getEnd);
  methods[4].selector = @selector(setEndWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "start_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "end_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "II", "setStart", "I", "setEnd", "LLibOrgBouncycastleCryptoTlsDTLSReassembler;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsDTLSReassembler_Range = { "Range", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0xa, 5, 2, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range;
}

@end

void LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *self, jint start, jint end) {
  NSObject_init(self);
  self->start_ = start;
  self->end_ = end;
}

LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *new_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(jint start, jint end) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range, initWithInt_withInt_, start, end)
}

LibOrgBouncycastleCryptoTlsDTLSReassembler_Range *create_LibOrgBouncycastleCryptoTlsDTLSReassembler_Range_initWithInt_withInt_(jint start, jint end) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range, initWithInt_withInt_, start, end)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsDTLSReassembler_Range)