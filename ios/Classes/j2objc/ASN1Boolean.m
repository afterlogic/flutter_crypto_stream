//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1Boolean.java
//

#include "ASN1Boolean.h"
#include "ASN1OctetString.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "BERTags.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1ASN1Boolean () {
 @public
  IOSByteArray *value_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1Boolean, value_, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleAsn1ASN1Boolean_get_TRUE_VALUE(void);
static IOSByteArray *LibOrgBouncycastleAsn1ASN1Boolean_TRUE_VALUE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1ASN1Boolean, TRUE_VALUE, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleAsn1ASN1Boolean_get_FALSE_VALUE(void);
static IOSByteArray *LibOrgBouncycastleAsn1ASN1Boolean_FALSE_VALUE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1ASN1Boolean, FALSE_VALUE, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1ASN1Boolean)

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_FALSE;
LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_TRUE;

@implementation LibOrgBouncycastleAsn1ASN1Boolean

+ (LibOrgBouncycastleAsn1ASN1Boolean *)FALSE_ {
  return LibOrgBouncycastleAsn1ASN1Boolean_FALSE;
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)TRUE_ {
  return LibOrgBouncycastleAsn1ASN1Boolean_TRUE;
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)getInstanceWithBoolean:(jboolean)value {
  return LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithBoolean_(value);
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)getInstanceWithInt:(jint)value {
  return LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithInt_(value);
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                 withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithByteArray:(IOSByteArray *)value {
  LibOrgBouncycastleAsn1ASN1Boolean_initWithByteArray_(self, value);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)value {
  LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(self, value);
  return self;
}

- (jboolean)isTrue {
  return (IOSByteArray_Get(nil_chk(value_), 0) != 0);
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  return 3;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:LibOrgBouncycastleAsn1BERTags_BOOLEAN withByteArray:value_];
}

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o {
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Boolean class]]) {
    return IOSByteArray_Get(nil_chk(value_), 0) == IOSByteArray_Get(((LibOrgBouncycastleAsn1ASN1Boolean *) nil_chk(((LibOrgBouncycastleAsn1ASN1Boolean *) o)))->value_, 0);
  }
  return false;
}

- (NSUInteger)hash {
  return IOSByteArray_Get(nil_chk(value_), 0);
}

- (NSString *)description {
  return (IOSByteArray_Get(nil_chk(value_), 0) != 0) ? @"TRUE" : @"FALSE";
}

+ (LibOrgBouncycastleAsn1ASN1Boolean *)fromOctetStringWithByteArray:(IOSByteArray *)value {
  return LibOrgBouncycastleAsn1ASN1Boolean_fromOctetStringWithByteArray_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x9, 0, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x9, 0, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 6, 7, 8, -1, -1, -1 },
    { NULL, "Z", 0x4, 9, 10, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 11, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 12, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x8, 13, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithBoolean:);
  methods[2].selector = @selector(getInstanceWithInt:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(initWithByteArray:);
  methods[5].selector = @selector(initWithBoolean:);
  methods[6].selector = @selector(isTrue);
  methods[7].selector = @selector(isConstructed);
  methods[8].selector = @selector(encodedLength);
  methods[9].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  methods[10].selector = @selector(asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[11].selector = @selector(hash);
  methods[12].selector = @selector(description);
  methods[13].selector = @selector(fromOctetStringWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TRUE_VALUE", "[B", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "FALSE_VALUE", "[B", .constantValue.asLong = 0, 0x1a, -1, 15, -1, -1 },
    { "value_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "FALSE", "LLibOrgBouncycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "TRUE", "LLibOrgBouncycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x19, -1, 17, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "Z", "I", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "[B", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;", "LJavaIoIOException;", "asn1Equals", "LLibOrgBouncycastleAsn1ASN1Primitive;", "hashCode", "toString", "fromOctetString", &LibOrgBouncycastleAsn1ASN1Boolean_TRUE_VALUE, &LibOrgBouncycastleAsn1ASN1Boolean_FALSE_VALUE, &LibOrgBouncycastleAsn1ASN1Boolean_FALSE, &LibOrgBouncycastleAsn1ASN1Boolean_TRUE };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1Boolean = { "ASN1Boolean", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 14, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1Boolean;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1ASN1Boolean class]) {
    LibOrgBouncycastleAsn1ASN1Boolean_TRUE_VALUE = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0xff } count:1];
    LibOrgBouncycastleAsn1ASN1Boolean_FALSE_VALUE = [IOSByteArray newArrayWithBytes:(jbyte[]){ 0 } count:1];
    LibOrgBouncycastleAsn1ASN1Boolean_FALSE = new_LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(false);
    LibOrgBouncycastleAsn1ASN1Boolean_TRUE = new_LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(true);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1ASN1Boolean)
  }
}

@end

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1ASN1Boolean_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Boolean class]]) {
    return (LibOrgBouncycastleAsn1ASN1Boolean *) cast_chk(obj, [LibOrgBouncycastleAsn1ASN1Boolean class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    IOSByteArray *enc = (IOSByteArray *) cast_chk(obj, [IOSByteArray class]);
    @try {
      return (LibOrgBouncycastleAsn1ASN1Boolean *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(enc), [LibOrgBouncycastleAsn1ASN1Boolean class]);
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"failed to construct boolean from byte[]: ", [e getMessage]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithBoolean_(jboolean value) {
  LibOrgBouncycastleAsn1ASN1Boolean_initialize();
  return (value ? LibOrgBouncycastleAsn1ASN1Boolean_TRUE : LibOrgBouncycastleAsn1ASN1Boolean_FALSE);
}

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithInt_(jint value) {
  LibOrgBouncycastleAsn1ASN1Boolean_initialize();
  return (value != 0 ? LibOrgBouncycastleAsn1ASN1Boolean_TRUE : LibOrgBouncycastleAsn1ASN1Boolean_FALSE);
}

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1ASN1Boolean_initialize();
  LibOrgBouncycastleAsn1ASN1Primitive *o = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Boolean class]]) {
    return LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_(o);
  }
  else {
    return LibOrgBouncycastleAsn1ASN1Boolean_fromOctetStringWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(((LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk(o, [LibOrgBouncycastleAsn1ASN1OctetString class])))) getOctets]);
  }
}

void LibOrgBouncycastleAsn1ASN1Boolean_initWithByteArray_(LibOrgBouncycastleAsn1ASN1Boolean *self, IOSByteArray *value) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  if (((IOSByteArray *) nil_chk(value))->size_ != 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"byte value should have 1 byte in it");
  }
  if (IOSByteArray_Get(value, 0) == 0) {
    self->value_ = LibOrgBouncycastleAsn1ASN1Boolean_FALSE_VALUE;
  }
  else if ((IOSByteArray_Get(value, 0) & (jint) 0xff) == (jint) 0xff) {
    self->value_ = LibOrgBouncycastleAsn1ASN1Boolean_TRUE_VALUE;
  }
  else {
    self->value_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(value);
  }
}

LibOrgBouncycastleAsn1ASN1Boolean *new_LibOrgBouncycastleAsn1ASN1Boolean_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1Boolean, initWithByteArray_, value)
}

LibOrgBouncycastleAsn1ASN1Boolean *create_LibOrgBouncycastleAsn1ASN1Boolean_initWithByteArray_(IOSByteArray *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1Boolean, initWithByteArray_, value)
}

void LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(LibOrgBouncycastleAsn1ASN1Boolean *self, jboolean value) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->value_ = (value) ? LibOrgBouncycastleAsn1ASN1Boolean_TRUE_VALUE : LibOrgBouncycastleAsn1ASN1Boolean_FALSE_VALUE;
}

LibOrgBouncycastleAsn1ASN1Boolean *new_LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(jboolean value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1Boolean, initWithBoolean_, value)
}

LibOrgBouncycastleAsn1ASN1Boolean *create_LibOrgBouncycastleAsn1ASN1Boolean_initWithBoolean_(jboolean value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1Boolean, initWithBoolean_, value)
}

LibOrgBouncycastleAsn1ASN1Boolean *LibOrgBouncycastleAsn1ASN1Boolean_fromOctetStringWithByteArray_(IOSByteArray *value) {
  LibOrgBouncycastleAsn1ASN1Boolean_initialize();
  if (((IOSByteArray *) nil_chk(value))->size_ != 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"BOOLEAN value should have 1 byte in it");
  }
  if (IOSByteArray_Get(value, 0) == 0) {
    return LibOrgBouncycastleAsn1ASN1Boolean_FALSE;
  }
  else if ((IOSByteArray_Get(value, 0) & (jint) 0xff) == (jint) 0xff) {
    return LibOrgBouncycastleAsn1ASN1Boolean_TRUE;
  }
  else {
    return new_LibOrgBouncycastleAsn1ASN1Boolean_initWithByteArray_(value);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1Boolean)
