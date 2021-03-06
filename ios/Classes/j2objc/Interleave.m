//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/raw/Interleave.java
//

#include "IOSPrimitiveArray.h"
#include "Interleave.h"
#include "J2ObjC_source.h"

inline jlong LibOrgBouncycastleMathRawInterleave_get_M32(void);
#define LibOrgBouncycastleMathRawInterleave_M32 1431655765LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathRawInterleave, M32, jlong)

inline jlong LibOrgBouncycastleMathRawInterleave_get_M64(void);
#define LibOrgBouncycastleMathRawInterleave_M64 6148914691236517205LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathRawInterleave, M64, jlong)

inline jlong LibOrgBouncycastleMathRawInterleave_get_M64R(void);
#define LibOrgBouncycastleMathRawInterleave_M64R -6148914691236517206LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathRawInterleave, M64R, jlong)

@implementation LibOrgBouncycastleMathRawInterleave

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathRawInterleave_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jint)expand8to16WithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_expand8to16WithInt_(x);
}

+ (jint)expand16to32WithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_expand16to32WithInt_(x);
}

+ (jlong)expand32to64WithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_expand32to64WithInt_(x);
}

+ (void)expand64To128WithLong:(jlong)x
                withLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff {
  LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(x, z, zOff);
}

+ (void)expand64To128RevWithLong:(jlong)x
                   withLongArray:(IOSLongArray *)z
                         withInt:(jint)zOff {
  LibOrgBouncycastleMathRawInterleave_expand64To128RevWithLong_withLongArray_withInt_(x, z, zOff);
}

+ (jint)shuffleWithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_shuffleWithInt_(x);
}

+ (jlong)shuffleWithLong:(jlong)x {
  return LibOrgBouncycastleMathRawInterleave_shuffleWithLong_(x);
}

+ (jint)shuffle2WithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_shuffle2WithInt_(x);
}

+ (jint)unshuffleWithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_unshuffleWithInt_(x);
}

+ (jlong)unshuffleWithLong:(jlong)x {
  return LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(x);
}

+ (jint)unshuffle2WithInt:(jint)x {
  return LibOrgBouncycastleMathRawInterleave_unshuffle2WithInt_(x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 3, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 6, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 7, 1, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 9, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 10, 1, -1, -1, -1, -1 },
    { NULL, "J", 0x9, 10, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 11, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(expand8to16WithInt:);
  methods[2].selector = @selector(expand16to32WithInt:);
  methods[3].selector = @selector(expand32to64WithInt:);
  methods[4].selector = @selector(expand64To128WithLong:withLongArray:withInt:);
  methods[5].selector = @selector(expand64To128RevWithLong:withLongArray:withInt:);
  methods[6].selector = @selector(shuffleWithInt:);
  methods[7].selector = @selector(shuffleWithLong:);
  methods[8].selector = @selector(shuffle2WithInt:);
  methods[9].selector = @selector(unshuffleWithInt:);
  methods[10].selector = @selector(unshuffleWithLong:);
  methods[11].selector = @selector(unshuffle2WithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "M32", "J", .constantValue.asLong = LibOrgBouncycastleMathRawInterleave_M32, 0x1a, -1, -1, -1, -1 },
    { "M64", "J", .constantValue.asLong = LibOrgBouncycastleMathRawInterleave_M64, 0x1a, -1, -1, -1, -1 },
    { "M64R", "J", .constantValue.asLong = LibOrgBouncycastleMathRawInterleave_M64R, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "expand8to16", "I", "expand16to32", "expand32to64", "expand64To128", "J[JI", "expand64To128Rev", "shuffle", "J", "shuffle2", "unshuffle", "unshuffle2" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathRawInterleave = { "Interleave", "lib.org.bouncycastle.math.raw", ptrTable, methods, fields, 7, 0x1, 12, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathRawInterleave;
}

@end

void LibOrgBouncycastleMathRawInterleave_init(LibOrgBouncycastleMathRawInterleave *self) {
  NSObject_init(self);
}

LibOrgBouncycastleMathRawInterleave *new_LibOrgBouncycastleMathRawInterleave_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathRawInterleave, init)
}

LibOrgBouncycastleMathRawInterleave *create_LibOrgBouncycastleMathRawInterleave_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathRawInterleave, init)
}

jint LibOrgBouncycastleMathRawInterleave_expand8to16WithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  x &= (jint) 0xFF;
  x = (x | (JreLShift32(x, 4))) & (jint) 0x0F0F;
  x = (x | (JreLShift32(x, 2))) & (jint) 0x3333;
  x = (x | (JreLShift32(x, 1))) & (jint) 0x5555;
  return x;
}

jint LibOrgBouncycastleMathRawInterleave_expand16to32WithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  x &= (jint) 0xFFFF;
  x = (x | (JreLShift32(x, 8))) & (jint) 0x00FF00FF;
  x = (x | (JreLShift32(x, 4))) & (jint) 0x0F0F0F0F;
  x = (x | (JreLShift32(x, 2))) & (jint) 0x33333333;
  x = (x | (JreLShift32(x, 1))) & (jint) 0x55555555;
  return x;
}

jlong LibOrgBouncycastleMathRawInterleave_expand32to64WithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jint t;
  t = (x ^ (JreURShift32(x, 8))) & (jint) 0x0000FF00;
  x ^= (t ^ (JreLShift32(t, 8)));
  t = (x ^ (JreURShift32(x, 4))) & (jint) 0x00F000F0;
  x ^= (t ^ (JreLShift32(t, 4)));
  t = (x ^ (JreURShift32(x, 2))) & (jint) 0x0C0C0C0C;
  x ^= (t ^ (JreLShift32(t, 2)));
  t = (x ^ (JreURShift32(x, 1))) & (jint) 0x22222222;
  x ^= (t ^ (JreLShift32(t, 1)));
  return (JreLShift64(((JreURShift32(x, 1)) & LibOrgBouncycastleMathRawInterleave_M32), 32)) | (x & LibOrgBouncycastleMathRawInterleave_M32);
}

void LibOrgBouncycastleMathRawInterleave_expand64To128WithLong_withLongArray_withInt_(jlong x, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jlong t;
  t = (x ^ (JreURShift64(x, 16))) & (jlong) 0x00000000FFFF0000LL;
  x ^= (t ^ (JreLShift64(t, 16)));
  t = (x ^ (JreURShift64(x, 8))) & (jlong) 0x0000FF000000FF00LL;
  x ^= (t ^ (JreLShift64(t, 8)));
  t = (x ^ (JreURShift64(x, 4))) & (jlong) 0x00F000F000F000F0LL;
  x ^= (t ^ (JreLShift64(t, 4)));
  t = (x ^ (JreURShift64(x, 2))) & (jlong) 0x0C0C0C0C0C0C0C0CLL;
  x ^= (t ^ (JreLShift64(t, 2)));
  t = (x ^ (JreURShift64(x, 1))) & (jlong) 0x2222222222222222LL;
  x ^= (t ^ (JreLShift64(t, 1)));
  *IOSLongArray_GetRef(nil_chk(z), zOff) = (x) & LibOrgBouncycastleMathRawInterleave_M64;
  *IOSLongArray_GetRef(z, zOff + 1) = (JreURShift64(x, 1)) & LibOrgBouncycastleMathRawInterleave_M64;
}

void LibOrgBouncycastleMathRawInterleave_expand64To128RevWithLong_withLongArray_withInt_(jlong x, IOSLongArray *z, jint zOff) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jlong t;
  t = (x ^ (JreURShift64(x, 16))) & (jlong) 0x00000000FFFF0000LL;
  x ^= (t ^ (JreLShift64(t, 16)));
  t = (x ^ (JreURShift64(x, 8))) & (jlong) 0x0000FF000000FF00LL;
  x ^= (t ^ (JreLShift64(t, 8)));
  t = (x ^ (JreURShift64(x, 4))) & (jlong) 0x00F000F000F000F0LL;
  x ^= (t ^ (JreLShift64(t, 4)));
  t = (x ^ (JreURShift64(x, 2))) & (jlong) 0x0C0C0C0C0C0C0C0CLL;
  x ^= (t ^ (JreLShift64(t, 2)));
  t = (x ^ (JreURShift64(x, 1))) & (jlong) 0x2222222222222222LL;
  x ^= (t ^ (JreLShift64(t, 1)));
  *IOSLongArray_GetRef(nil_chk(z), zOff) = (x) & LibOrgBouncycastleMathRawInterleave_M64R;
  *IOSLongArray_GetRef(z, zOff + 1) = (JreLShift64(x, 1)) & LibOrgBouncycastleMathRawInterleave_M64R;
}

jint LibOrgBouncycastleMathRawInterleave_shuffleWithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jint t;
  t = (x ^ (JreURShift32(x, 8))) & (jint) 0x0000FF00;
  x ^= (t ^ (JreLShift32(t, 8)));
  t = (x ^ (JreURShift32(x, 4))) & (jint) 0x00F000F0;
  x ^= (t ^ (JreLShift32(t, 4)));
  t = (x ^ (JreURShift32(x, 2))) & (jint) 0x0C0C0C0C;
  x ^= (t ^ (JreLShift32(t, 2)));
  t = (x ^ (JreURShift32(x, 1))) & (jint) 0x22222222;
  x ^= (t ^ (JreLShift32(t, 1)));
  return x;
}

jlong LibOrgBouncycastleMathRawInterleave_shuffleWithLong_(jlong x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jlong t;
  t = (x ^ (JreURShift64(x, 16))) & (jlong) 0x00000000FFFF0000LL;
  x ^= (t ^ (JreLShift64(t, 16)));
  t = (x ^ (JreURShift64(x, 8))) & (jlong) 0x0000FF000000FF00LL;
  x ^= (t ^ (JreLShift64(t, 8)));
  t = (x ^ (JreURShift64(x, 4))) & (jlong) 0x00F000F000F000F0LL;
  x ^= (t ^ (JreLShift64(t, 4)));
  t = (x ^ (JreURShift64(x, 2))) & (jlong) 0x0C0C0C0C0C0C0C0CLL;
  x ^= (t ^ (JreLShift64(t, 2)));
  t = (x ^ (JreURShift64(x, 1))) & (jlong) 0x2222222222222222LL;
  x ^= (t ^ (JreLShift64(t, 1)));
  return x;
}

jint LibOrgBouncycastleMathRawInterleave_shuffle2WithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jint t;
  t = (x ^ (JreURShift32(x, 7))) & (jint) 0x00AA00AA;
  x ^= (t ^ (JreLShift32(t, 7)));
  t = (x ^ (JreURShift32(x, 14))) & (jint) 0x0000CCCC;
  x ^= (t ^ (JreLShift32(t, 14)));
  t = (x ^ (JreURShift32(x, 4))) & (jint) 0x00F000F0;
  x ^= (t ^ (JreLShift32(t, 4)));
  t = (x ^ (JreURShift32(x, 8))) & (jint) 0x0000FF00;
  x ^= (t ^ (JreLShift32(t, 8)));
  return x;
}

jint LibOrgBouncycastleMathRawInterleave_unshuffleWithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jint t;
  t = (x ^ (JreURShift32(x, 1))) & (jint) 0x22222222;
  x ^= (t ^ (JreLShift32(t, 1)));
  t = (x ^ (JreURShift32(x, 2))) & (jint) 0x0C0C0C0C;
  x ^= (t ^ (JreLShift32(t, 2)));
  t = (x ^ (JreURShift32(x, 4))) & (jint) 0x00F000F0;
  x ^= (t ^ (JreLShift32(t, 4)));
  t = (x ^ (JreURShift32(x, 8))) & (jint) 0x0000FF00;
  x ^= (t ^ (JreLShift32(t, 8)));
  return x;
}

jlong LibOrgBouncycastleMathRawInterleave_unshuffleWithLong_(jlong x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jlong t;
  t = (x ^ (JreURShift64(x, 1))) & (jlong) 0x2222222222222222LL;
  x ^= (t ^ (JreLShift64(t, 1)));
  t = (x ^ (JreURShift64(x, 2))) & (jlong) 0x0C0C0C0C0C0C0C0CLL;
  x ^= (t ^ (JreLShift64(t, 2)));
  t = (x ^ (JreURShift64(x, 4))) & (jlong) 0x00F000F000F000F0LL;
  x ^= (t ^ (JreLShift64(t, 4)));
  t = (x ^ (JreURShift64(x, 8))) & (jlong) 0x0000FF000000FF00LL;
  x ^= (t ^ (JreLShift64(t, 8)));
  t = (x ^ (JreURShift64(x, 16))) & (jlong) 0x00000000FFFF0000LL;
  x ^= (t ^ (JreLShift64(t, 16)));
  return x;
}

jint LibOrgBouncycastleMathRawInterleave_unshuffle2WithInt_(jint x) {
  LibOrgBouncycastleMathRawInterleave_initialize();
  jint t;
  t = (x ^ (JreURShift32(x, 8))) & (jint) 0x0000FF00;
  x ^= (t ^ (JreLShift32(t, 8)));
  t = (x ^ (JreURShift32(x, 4))) & (jint) 0x00F000F0;
  x ^= (t ^ (JreLShift32(t, 4)));
  t = (x ^ (JreURShift32(x, 14))) & (jint) 0x0000CCCC;
  x ^= (t ^ (JreLShift32(t, 14)));
  t = (x ^ (JreURShift32(x, 7))) & (jint) 0x00AA00AA;
  x ^= (t ^ (JreLShift32(t, 7)));
  return x;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathRawInterleave)
