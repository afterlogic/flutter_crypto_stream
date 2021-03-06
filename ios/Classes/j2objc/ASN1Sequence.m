//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1Sequence.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1SequenceParser.h"
#include "ASN1Set.h"
#include "ASN1SetParser.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "BERSequence.h"
#include "BERTaggedObject.h"
#include "DERSequence.h"
#include "DLSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Iterable.h"
#include "java/util/Enumeration.h"
#include "java/util/Iterator.h"
#include "java/util/Spliterator.h"
#include "java/util/Vector.h"
#include "java/util/function/Consumer.h"

@interface LibOrgBouncycastleAsn1ASN1Sequence ()

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getNextWithJavaUtilEnumeration:(id<JavaUtilEnumeration>)e;

@end

__attribute__((unused)) static id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(LibOrgBouncycastleAsn1ASN1Sequence *self, id<JavaUtilEnumeration> e);

@interface LibOrgBouncycastleAsn1ASN1Sequence_1 : NSObject < LibOrgBouncycastleAsn1ASN1SequenceParser > {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *this$0_;
  LibOrgBouncycastleAsn1ASN1Sequence *val$outer_;
  jint max_;
  jint index_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)outer$
                    withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)capture$0;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readObject;

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1Sequence_1)

__attribute__((unused)) static void LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_1 *self, LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence_1 *new_LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence_1 *create_LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0);

@implementation LibOrgBouncycastleAsn1ASN1Sequence

+ (LibOrgBouncycastleAsn1ASN1Sequence *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1ASN1Sequence *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1ASN1Sequence_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(self, obj);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(self, v);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)array {
  LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(self, array);
  return self;
}

- (IOSObjectArray *)toArray {
  IOSObjectArray *values = [IOSObjectArray newArrayWithLength:[self size] type:LibOrgBouncycastleAsn1ASN1Encodable_class_()];
  for (jint i = 0; i != [self size]; i++) {
    (void) IOSObjectArray_Set(values, i, [self getObjectAtWithInt:i]);
  }
  return values;
}

- (id<JavaUtilEnumeration>)getObjects {
  return [((JavaUtilVector *) nil_chk(seq_)) elements];
}

- (id<LibOrgBouncycastleAsn1ASN1SequenceParser>)parser {
  LibOrgBouncycastleAsn1ASN1Sequence *outer = self;
  return new_LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(self, outer);
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getObjectAtWithInt:(jint)index {
  return (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([((JavaUtilVector *) nil_chk(seq_)) elementAtWithInt:index], LibOrgBouncycastleAsn1ASN1Encodable_class_());
}

- (jint)size {
  return [((JavaUtilVector *) nil_chk(seq_)) size];
}

- (NSUInteger)hash {
  id<JavaUtilEnumeration> e = [self getObjects];
  jint hashCode = [self size];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    id o = LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(self, e);
    hashCode *= 17;
    hashCode ^= ((jint) [nil_chk(o) hash]);
  }
  return hashCode;
}

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]])) {
    return false;
  }
  LibOrgBouncycastleAsn1ASN1Sequence *other = (LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk(o, [LibOrgBouncycastleAsn1ASN1Sequence class]);
  if ([self size] != [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(other)) size]) {
    return false;
  }
  id<JavaUtilEnumeration> s1 = [self getObjects];
  id<JavaUtilEnumeration> s2 = [other getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(s1)) hasMoreElements]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> obj1 = LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(self, s1);
    id<LibOrgBouncycastleAsn1ASN1Encodable> obj2 = LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(self, s2);
    LibOrgBouncycastleAsn1ASN1Primitive *o1 = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(obj1)) toASN1Primitive];
    LibOrgBouncycastleAsn1ASN1Primitive *o2 = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(obj2)) toASN1Primitive];
    if (o1 == o2 || [((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk(o1)) isEqual:o2]) {
      continue;
    }
    return false;
  }
  return true;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getNextWithJavaUtilEnumeration:(id<JavaUtilEnumeration>)e {
  return LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(self, e);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject {
  LibOrgBouncycastleAsn1ASN1Sequence *derSeq = new_LibOrgBouncycastleAsn1DERSequence_init();
  derSeq->seq_ = self->seq_;
  return derSeq;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDLObject {
  LibOrgBouncycastleAsn1ASN1Sequence *dlSeq = new_LibOrgBouncycastleAsn1DLSequence_init();
  dlSeq->seq_ = self->seq_;
  return dlSeq;
}

- (jboolean)isConstructed {
  return true;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (NSString *)description {
  return [((JavaUtilVector *) nil_chk(seq_)) description];
}

- (id<JavaUtilIterator>)iterator {
  return new_LibOrgBouncycastleUtilArrays_Iterator_initWithNSObjectArray_([self toArray]);
}

- (void)forEachWithJavaUtilFunctionConsumer:(id<JavaUtilFunctionConsumer>)arg0 {
  JavaLangIterable_forEachWithJavaUtilFunctionConsumer_(self, arg0);
}

- (id<JavaUtilSpliterator>)spliterator {
  return JavaLangIterable_spliterator(self);
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 5, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1SequenceParser;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, 9, 10, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x400, 13, 14, 15, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 16, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x1, -1, -1, -1, 17, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(init);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1EncodableVector:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1EncodableArray:);
  methods[6].selector = @selector(toArray);
  methods[7].selector = @selector(getObjects);
  methods[8].selector = @selector(parser);
  methods[9].selector = @selector(getObjectAtWithInt:);
  methods[10].selector = @selector(size);
  methods[11].selector = @selector(hash);
  methods[12].selector = @selector(asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[13].selector = @selector(getNextWithJavaUtilEnumeration:);
  methods[14].selector = @selector(toDERObject);
  methods[15].selector = @selector(toDLObject);
  methods[16].selector = @selector(isConstructed);
  methods[17].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  methods[18].selector = @selector(description);
  methods[19].selector = @selector(iterator);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1ASN1Encodable;", "LLibOrgBouncycastleAsn1ASN1EncodableVector;", "[LLibOrgBouncycastleAsn1ASN1Encodable;", "getObjectAt", "I", "hashCode", "asn1Equals", "LLibOrgBouncycastleAsn1ASN1Primitive;", "getNext", "LJavaUtilEnumeration;", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;", "LJavaIoIOException;", "toString", "()Ljava/util/Iterator<Llib/org/bouncycastle/asn1/ASN1Encodable;>;", "Llib/org/bouncycastle/asn1/ASN1Primitive;Llib/org/bouncycastle/util/Iterable<Llib/org/bouncycastle/asn1/ASN1Encodable;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1Sequence = { "ASN1Sequence", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x401, 20, 1, -1, -1, -1, 18, -1 };
  return &_LibOrgBouncycastleAsn1ASN1Sequence;
}

@end

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1ASN1Sequence_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return (LibOrgBouncycastleAsn1ASN1Sequence *) cast_chk(obj, [LibOrgBouncycastleAsn1ASN1Sequence class]);
  }
  else if ([LibOrgBouncycastleAsn1ASN1SequenceParser_class_() isInstance:obj]) {
    return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((id<LibOrgBouncycastleAsn1ASN1SequenceParser>) cast_check(obj, LibOrgBouncycastleAsn1ASN1SequenceParser_class_())) toASN1Primitive]);
  }
  else if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"failed to construct sequence from byte[]: ", [e getMessage]));
    }
  }
  else if ([LibOrgBouncycastleAsn1ASN1Encodable_class_() isInstance:obj]) {
    LibOrgBouncycastleAsn1ASN1Primitive *primitive = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())) toASN1Primitive];
    if ([primitive isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
      return (LibOrgBouncycastleAsn1ASN1Sequence *) primitive;
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in getInstance: ", [[obj java_getClass] getName]));
}

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1ASN1Sequence_initialize();
  if (explicit_) {
    if (![((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) isExplicit]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"object implicit - explicit expected.");
    }
    return LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([obj getObject])) toASN1Primitive]);
  }
  else {
    LibOrgBouncycastleAsn1ASN1Primitive *o = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
    if ([obj isExplicit]) {
      if ([obj isKindOfClass:[LibOrgBouncycastleAsn1BERTaggedObject class]]) {
        return new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(o);
      }
      else {
        return new_LibOrgBouncycastleAsn1DLSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(o);
      }
    }
    else {
      if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
        return (LibOrgBouncycastleAsn1ASN1Sequence *) o;
      }
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in getInstance: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1ASN1Sequence_init(LibOrgBouncycastleAsn1ASN1Sequence *self) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->seq_ = new_JavaUtilVector_init();
}

void LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1Sequence *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->seq_ = new_JavaUtilVector_init();
  [self->seq_ addElementWithId:obj];
}

void LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1ASN1Sequence *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->seq_ = new_JavaUtilVector_init();
  for (jint i = 0; i != [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) size]; i++) {
    [((JavaUtilVector *) nil_chk(self->seq_)) addElementWithId:[v getWithInt:i]];
  }
}

void LibOrgBouncycastleAsn1ASN1Sequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(LibOrgBouncycastleAsn1ASN1Sequence *self, IOSObjectArray *array) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->seq_ = new_JavaUtilVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(array))->size_; i++) {
    [((JavaUtilVector *) nil_chk(self->seq_)) addElementWithId:IOSObjectArray_Get(array, i)];
  }
}

id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleAsn1ASN1Sequence_getNextWithJavaUtilEnumeration_(LibOrgBouncycastleAsn1ASN1Sequence *self, id<JavaUtilEnumeration> e) {
  id<LibOrgBouncycastleAsn1ASN1Encodable> encObj = (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_());
  return encObj;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1Sequence)

@implementation LibOrgBouncycastleAsn1ASN1Sequence_1

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)outer$
                    withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)capture$0 {
  LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(self, outer$, capture$0);
  return self;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)readObject {
  if (index_ == max_) {
    return nil;
  }
  id<LibOrgBouncycastleAsn1ASN1Encodable> obj = [this$0_ getObjectAtWithInt:index_++];
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(((LibOrgBouncycastleAsn1ASN1Sequence *) obj))) parser];
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Set class]]) {
    return [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(((LibOrgBouncycastleAsn1ASN1Set *) obj))) parser];
  }
  return obj;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject {
  return val$outer_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return val$outer_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, -1, -1, 0, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(readObject);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$outer_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "max_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "index_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoIOException;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "parser" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1Sequence_1 = { "", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x8010, 4, 4, 1, -1, 2, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1Sequence_1;
}

@end

void LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_1 *self, LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0) {
  self->this$0_ = outer$;
  self->val$outer_ = capture$0;
  NSObject_init(self);
  self->max_ = [outer$ size];
}

LibOrgBouncycastleAsn1ASN1Sequence_1 *new_LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1Sequence_1, initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_, outer$, capture$0)
}

LibOrgBouncycastleAsn1ASN1Sequence_1 *create_LibOrgBouncycastleAsn1ASN1Sequence_1_initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *outer$, LibOrgBouncycastleAsn1ASN1Sequence *capture$0) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1Sequence_1, initWithLibOrgBouncycastleAsn1ASN1Sequence_withLibOrgBouncycastleAsn1ASN1Sequence_, outer$, capture$0)
}
