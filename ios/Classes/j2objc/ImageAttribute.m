//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/attr/ImageAttribute.java
//

#include "IOSPrimitiveArray.h"
#include "ImageAttribute.h"
#include "J2ObjC_source.h"
#include "UserAttributeSubpacket.h"
#include "UserAttributeSubpacketTags.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleBcpgAttrImageAttribute () {
 @public
  jint hdrLength_;
  jint version__;
  jint encoding_;
  IOSByteArray *imageData_;
}

+ (IOSByteArray *)toByteArrayWithInt:(jint)imageType
                       withByteArray:(IOSByteArray *)imageData;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgAttrImageAttribute, imageData_, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleBcpgAttrImageAttribute_get_ZEROES(void);
static IOSByteArray *LibOrgBouncycastleBcpgAttrImageAttribute_ZEROES;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleBcpgAttrImageAttribute, ZEROES, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleBcpgAttrImageAttribute_toByteArrayWithInt_withByteArray_(jint imageType, IOSByteArray *imageData);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleBcpgAttrImageAttribute)

@implementation LibOrgBouncycastleBcpgAttrImageAttribute

+ (jint)JPEG {
  return LibOrgBouncycastleBcpgAttrImageAttribute_JPEG;
}

- (instancetype)initWithByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleBcpgAttrImageAttribute_initWithByteArray_(self, data);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)forceLongLength
                  withByteArray:(IOSByteArray *)data {
  LibOrgBouncycastleBcpgAttrImageAttribute_initWithBoolean_withByteArray_(self, forceLongLength, data);
  return self;
}

- (instancetype)initWithInt:(jint)imageType
              withByteArray:(IOSByteArray *)imageData {
  LibOrgBouncycastleBcpgAttrImageAttribute_initWithInt_withByteArray_(self, imageType, imageData);
  return self;
}

+ (IOSByteArray *)toByteArrayWithInt:(jint)imageType
                       withByteArray:(IOSByteArray *)imageData {
  return LibOrgBouncycastleBcpgAttrImageAttribute_toByteArrayWithInt_withByteArray_(imageType, imageData);
}

- (jint)version__ {
  return version__;
}

- (jint)getEncoding {
  return encoding_;
}

- (IOSByteArray *)getImageData {
  return imageData_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 3, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(initWithBoolean:withByteArray:);
  methods[2].selector = @selector(initWithInt:withByteArray:);
  methods[3].selector = @selector(toByteArrayWithInt:withByteArray:);
  methods[4].selector = @selector(version__);
  methods[5].selector = @selector(getEncoding);
  methods[6].selector = @selector(getImageData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "JPEG", "I", .constantValue.asInt = LibOrgBouncycastleBcpgAttrImageAttribute_JPEG, 0x19, -1, -1, -1, -1 },
    { "ZEROES", "[B", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "hdrLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "version__", "I", .constantValue.asLong = 0, 0x2, 4, -1, -1, -1 },
    { "encoding_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "imageData_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "Z[B", "I[B", "toByteArray", "version", &LibOrgBouncycastleBcpgAttrImageAttribute_ZEROES };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgAttrImageAttribute = { "ImageAttribute", "lib.org.bouncycastle.bcpg.attr", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgAttrImageAttribute;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleBcpgAttrImageAttribute class]) {
    LibOrgBouncycastleBcpgAttrImageAttribute_ZEROES = [IOSByteArray newArrayWithLength:12];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleBcpgAttrImageAttribute)
  }
}

@end

void LibOrgBouncycastleBcpgAttrImageAttribute_initWithByteArray_(LibOrgBouncycastleBcpgAttrImageAttribute *self, IOSByteArray *data) {
  LibOrgBouncycastleBcpgAttrImageAttribute_initWithBoolean_withByteArray_(self, false, data);
}

LibOrgBouncycastleBcpgAttrImageAttribute *new_LibOrgBouncycastleBcpgAttrImageAttribute_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithByteArray_, data)
}

LibOrgBouncycastleBcpgAttrImageAttribute *create_LibOrgBouncycastleBcpgAttrImageAttribute_initWithByteArray_(IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithByteArray_, data)
}

void LibOrgBouncycastleBcpgAttrImageAttribute_initWithBoolean_withByteArray_(LibOrgBouncycastleBcpgAttrImageAttribute *self, jboolean forceLongLength, IOSByteArray *data) {
  LibOrgBouncycastleBcpgUserAttributeSubpacket_initWithInt_withBoolean_withByteArray_(self, LibOrgBouncycastleBcpgUserAttributeSubpacketTags_IMAGE_ATTRIBUTE, forceLongLength, data);
  self->hdrLength_ = (JreLShift32((IOSByteArray_Get(nil_chk(data), 1) & (jint) 0xff), 8)) | (IOSByteArray_Get(data, 0) & (jint) 0xff);
  self->version__ = IOSByteArray_Get(data, 2) & (jint) 0xff;
  self->encoding_ = IOSByteArray_Get(data, 3) & (jint) 0xff;
  self->imageData_ = [IOSByteArray newArrayWithLength:data->size_ - self->hdrLength_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(data, self->hdrLength_, self->imageData_, 0, self->imageData_->size_);
}

LibOrgBouncycastleBcpgAttrImageAttribute *new_LibOrgBouncycastleBcpgAttrImageAttribute_initWithBoolean_withByteArray_(jboolean forceLongLength, IOSByteArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithBoolean_withByteArray_, forceLongLength, data)
}

LibOrgBouncycastleBcpgAttrImageAttribute *create_LibOrgBouncycastleBcpgAttrImageAttribute_initWithBoolean_withByteArray_(jboolean forceLongLength, IOSByteArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithBoolean_withByteArray_, forceLongLength, data)
}

void LibOrgBouncycastleBcpgAttrImageAttribute_initWithInt_withByteArray_(LibOrgBouncycastleBcpgAttrImageAttribute *self, jint imageType, IOSByteArray *imageData) {
  LibOrgBouncycastleBcpgAttrImageAttribute_initWithByteArray_(self, LibOrgBouncycastleBcpgAttrImageAttribute_toByteArrayWithInt_withByteArray_(imageType, imageData));
}

LibOrgBouncycastleBcpgAttrImageAttribute *new_LibOrgBouncycastleBcpgAttrImageAttribute_initWithInt_withByteArray_(jint imageType, IOSByteArray *imageData) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithInt_withByteArray_, imageType, imageData)
}

LibOrgBouncycastleBcpgAttrImageAttribute *create_LibOrgBouncycastleBcpgAttrImageAttribute_initWithInt_withByteArray_(jint imageType, IOSByteArray *imageData) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgAttrImageAttribute, initWithInt_withByteArray_, imageType, imageData)
}

IOSByteArray *LibOrgBouncycastleBcpgAttrImageAttribute_toByteArrayWithInt_withByteArray_(jint imageType, IOSByteArray *imageData) {
  LibOrgBouncycastleBcpgAttrImageAttribute_initialize();
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  @try {
    [bOut writeWithInt:(jint) 0x10];
    [bOut writeWithInt:(jint) 0x00];
    [bOut writeWithInt:(jint) 0x01];
    [bOut writeWithInt:imageType];
    [bOut writeWithByteArray:LibOrgBouncycastleBcpgAttrImageAttribute_ZEROES];
    [bOut writeWithByteArray:imageData];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"unable to encode to byte array!");
  }
  return [bOut toByteArray];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgAttrImageAttribute)
