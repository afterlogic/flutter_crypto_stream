//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/algorithm/PublicKeyAlgorithm.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PublicKeyAlgorithm.h"
#include "PublicKeyAlgorithmTags.h"
#include "java/lang/Enum.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/util/HashMap.h"
#include "java/util/Map.h"

@interface LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm () {
 @public
  jint algorithmId_;
}

@end

inline id<JavaUtilMap> LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_get_MAP(void);
static id<JavaUtilMap> LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_MAP;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, MAP, id<JavaUtilMap>)

__attribute__((unused)) static void LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *self, jint algorithmId, NSString *__name, jint __ordinal);

__attribute__((unused)) static LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(jint algorithmId, NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm)

LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values_[9];

@implementation LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)RSA_GENERAL {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_GENERAL);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)RSA_ENCRYPT {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_ENCRYPT);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)RSA_SIGN {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_SIGN);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)ELGAMAL_ENCRYPT {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_ENCRYPT);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)DSA {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DSA);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)ECDH {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDH);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)ECDSA {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDSA);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)ELGAMAL_GENERAL {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_GENERAL);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)DIFFIE_HELLMAN {
  return JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DIFFIE_HELLMAN);
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)fromIdWithInt:(jint)id_ {
  return LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_fromIdWithInt_(id_);
}

- (jint)getAlgorithmId {
  return algorithmId_;
}

+ (IOSObjectArray *)values {
  return LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values();
}

+ (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)valueOfWithNSString:(NSString *)name {
  return LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_valueOfWithNSString_(name);
}

- (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_Enum)toNSEnum {
  return (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_Enum)[self ordinal];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", 0x9, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(fromIdWithInt:);
  methods[1].selector = @selector(getAlgorithmId);
  methods[2].selector = @selector(values);
  methods[3].selector = @selector(valueOfWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "RSA_GENERAL", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 4, -1, -1 },
    { "RSA_ENCRYPT", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 5, -1, -1 },
    { "RSA_SIGN", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 6, -1, -1 },
    { "ELGAMAL_ENCRYPT", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 7, -1, -1 },
    { "DSA", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 8, -1, -1 },
    { "ECDH", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 9, -1, -1 },
    { "ECDSA", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 10, -1, -1 },
    { "ELGAMAL_GENERAL", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 11, -1, -1 },
    { "DIFFIE_HELLMAN", "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", .constantValue.asLong = 0, 0x4019, -1, 12, -1, -1 },
    { "MAP", "LJavaUtilMap;", .constantValue.asLong = 0, 0x1a, -1, 13, 14, -1 },
    { "algorithmId_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "fromId", "I", "valueOf", "LNSString;", &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_GENERAL), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_ENCRYPT), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_SIGN), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_ENCRYPT), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DSA), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDH), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDSA), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_GENERAL), &JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DIFFIE_HELLMAN), &LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_MAP, "Ljava/util/Map<Ljava/lang/Integer;Llib/com/afterlogic/pgp/algorithm/PublicKeyAlgorithm;>;", "Ljava/lang/Enum<Llib/com/afterlogic/pgp/algorithm/PublicKeyAlgorithm;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm = { "PublicKeyAlgorithm", "lib.com.afterlogic.pgp.algorithm", ptrTable, methods, fields, 7, 0x4011, 4, 11, -1, -1, -1, 15, -1 };
  return &_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm class]) {
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_GENERAL) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 0), 0);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_ENCRYPT) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 1), 1);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, RSA_SIGN) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 2), 2);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_ENCRYPT) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 3), 3);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DSA) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 4), 4);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDH) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 5), 5);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ECDSA) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDSA, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 6), 6);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_GENERAL) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 7), 7);
    JreEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, DIFFIE_HELLMAN) = new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DIFFIE_HELLMAN, JreEnumConstantName(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_(), 8), 8);
    LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_MAP = new_JavaUtilHashMap_init();
    {
      {
        IOSObjectArray *a__ = LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values();
        LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm * const *b__ = ((IOSObjectArray *) nil_chk(a__))->buffer_;
        LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm * const *e__ = b__ + a__->size_;
        while (b__ < e__) {
          LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *p = *b__++;
          (void) [LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_MAP putWithId:JavaLangInteger_valueOfWithInt_(((LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *) nil_chk(p))->algorithmId_) withId:p];
        }
      }
    }
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm)
  }
}

@end

LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_fromIdWithInt_(jint id_) {
  LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initialize();
  return [((id<JavaUtilMap>) nil_chk(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_MAP)) getWithId:JavaLangInteger_valueOfWithInt_(id_)];
}

void LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *self, jint algorithmId, NSString *__name, jint __ordinal) {
  JavaLangEnum_initWithNSString_withInt_(self, __name, __ordinal);
  self->algorithmId_ = algorithmId;
}

LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *new_LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initWithInt_withNSString_withInt_(jint algorithmId, NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, initWithInt_withNSString_withInt_, algorithmId, __name, __ordinal)
}

IOSObjectArray *LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values() {
  LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initialize();
  return [IOSObjectArray arrayWithObjects:LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values_ count:9 type:LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_class_()];
}

LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_valueOfWithNSString_(NSString *name) {
  LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initialize();
  for (int i = 0; i < 9; i++) {
    LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *e = LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values_[i];
    if ([name isEqual:[e name]]) {
      return e;
    }
  }
  @throw create_JavaLangIllegalArgumentException_initWithNSString_(name);
  return nil;
}

LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_fromOrdinal(NSUInteger ordinal) {
  LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_initialize();
  if (ordinal >= 9) {
    return nil;
  }
  return LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm_values_[ordinal];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm)