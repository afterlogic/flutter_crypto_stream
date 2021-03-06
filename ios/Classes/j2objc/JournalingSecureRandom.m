//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/JournalingSecureRandom.java
//

#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JournalingSecureRandom.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@class LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream;

@interface LibOrgBouncycastleCryptoUtilJournalingSecureRandom () {
 @public
  JavaSecuritySecureRandom *base_;
  IOSByteArray *transcript_;
  LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *tOut_;
  jint index_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, base_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, transcript_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, tOut_, LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *)

inline IOSByteArray *LibOrgBouncycastleCryptoUtilJournalingSecureRandom_get_EMPTY_TRANSCRIPT(void);
inline IOSByteArray *LibOrgBouncycastleCryptoUtilJournalingSecureRandom_set_EMPTY_TRANSCRIPT(IOSByteArray *value);
static IOSByteArray *LibOrgBouncycastleCryptoUtilJournalingSecureRandom_EMPTY_TRANSCRIPT;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, EMPTY_TRANSCRIPT, IOSByteArray *)

@interface LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream : JavaIoByteArrayOutputStream

- (instancetype)initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom:(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *)outer$;

- (void)clear;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream)

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *self, LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoUtilJournalingSecureRandom)

@implementation LibOrgBouncycastleCryptoUtilJournalingSecureRandom

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(self, random);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)transcript
     withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(self, transcript, random);
  return self;
}

- (void)nextBytesWithByteArray:(IOSByteArray *)bytes {
  if (index_ >= ((IOSByteArray *) nil_chk(transcript_))->size_) {
    [((JavaSecuritySecureRandom *) nil_chk(base_)) nextBytesWithByteArray:bytes];
  }
  else {
    jint i = 0;
    while (i != ((IOSByteArray *) nil_chk(bytes))->size_) {
      if (index_ < transcript_->size_) {
        *IOSByteArray_GetRef(bytes, i) = IOSByteArray_Get(transcript_, index_++);
      }
      else {
        break;
      }
      i++;
    }
    if (i != bytes->size_) {
      IOSByteArray *extra = [IOSByteArray newArrayWithLength:bytes->size_ - i];
      [((JavaSecuritySecureRandom *) nil_chk(base_)) nextBytesWithByteArray:extra];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(extra, 0, bytes, i, extra->size_);
    }
  }
  @try {
    [((LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *) nil_chk(tOut_)) writeWithByteArray:bytes];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"unable to record transcript: ", [e getMessage]));
  }
}

- (void)clear {
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(transcript_, (jbyte) 0);
  [((LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *) nil_chk(tOut_)) clear];
}

- (IOSByteArray *)getTranscript {
  return [((LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *) nil_chk(tOut_)) toByteArray];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x11, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithByteArray:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(nextBytesWithByteArray:);
  methods[3].selector = @selector(clear);
  methods[4].selector = @selector(getTranscript);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "EMPTY_TRANSCRIPT", "[B", .constantValue.asLong = 0, 0xa, -1, 4, -1, -1 },
    { "base_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "transcript_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "tOut_", "LLibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "index_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "[BLJavaSecuritySecureRandom;", "nextBytes", "[B", &LibOrgBouncycastleCryptoUtilJournalingSecureRandom_EMPTY_TRANSCRIPT, "LLibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilJournalingSecureRandom = { "JournalingSecureRandom", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x1, 5, 5, -1, 5, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilJournalingSecureRandom;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoUtilJournalingSecureRandom class]) {
    LibOrgBouncycastleCryptoUtilJournalingSecureRandom_EMPTY_TRANSCRIPT = [IOSByteArray newArrayWithLength:0];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoUtilJournalingSecureRandom)
  }
}

@end

void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *self, JavaSecuritySecureRandom *random) {
  JavaSecuritySecureRandom_init(self);
  self->tOut_ = new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(self);
  self->index_ = 0;
  self->base_ = random;
  self->transcript_ = LibOrgBouncycastleCryptoUtilJournalingSecureRandom_EMPTY_TRANSCRIPT;
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, initWithJavaSecuritySecureRandom_, random)
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, initWithJavaSecuritySecureRandom_, random)
}

void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *self, IOSByteArray *transcript, JavaSecuritySecureRandom *random) {
  JavaSecuritySecureRandom_init(self);
  self->tOut_ = new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(self);
  self->index_ = 0;
  self->base_ = random;
  self->transcript_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(transcript);
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(IOSByteArray *transcript, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, initWithByteArray_withJavaSecuritySecureRandom_, transcript, random)
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_initWithByteArray_withJavaSecuritySecureRandom_(IOSByteArray *transcript, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom, initWithByteArray_withJavaSecuritySecureRandom_, transcript, random)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilJournalingSecureRandom)

@implementation LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream

- (instancetype)initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom:(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *)outer$ {
  LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(self, outer$);
  return self;
}

- (void)clear {
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(buf_, (jbyte) 0);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom:);
  methods[1].selector = @selector(clear);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoUtilJournalingSecureRandom;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream = { "TranscriptStream", "lib.org.bouncycastle.crypto.util", ptrTable, methods, NULL, 7, 0x2, 2, 0, 0, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream;
}

@end

void LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *self, LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$) {
  JavaIoByteArrayOutputStream_init(self);
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *new_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream, initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_, outer$)
}

LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream *create_LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream_initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_(LibOrgBouncycastleCryptoUtilJournalingSecureRandom *outer$) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream, initWithLibOrgBouncycastleCryptoUtilJournalingSecureRandom_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilJournalingSecureRandom_TranscriptStream)
