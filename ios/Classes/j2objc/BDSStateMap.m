//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/BDSStateMap.java
//

#include "ASN1ObjectIdentifier.h"
#include "BDS.h"
#include "BDSStateMap.h"
#include "IOSPrimitiveArray.h"
#include "Integers.h"
#include "J2ObjC_source.h"
#include "OTSHashAddress.h"
#include "XMSSAddress.h"
#include "XMSSMTParameters.h"
#include "XMSSParameters.h"
#include "XMSSUtil.h"
#include "java/lang/Integer.h"
#include "java/util/Iterator.h"
#include "java/util/Map.h"
#include "java/util/Set.h"
#include "java/util/TreeMap.h"

@interface LibOrgBouncycastlePqcCryptoXmssBDSStateMap () {
 @public
  id<JavaUtilMap> bdsState_;
}

- (void)updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)params
                                                              withLong:(jlong)globalIndex
                                                         withByteArray:(IOSByteArray *)publicSeed
                                                         withByteArray:(IOSByteArray *)secretKeySeed;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, bdsState_, id<JavaUtilMap>)

inline jlong LibOrgBouncycastlePqcCryptoXmssBDSStateMap_get_serialVersionUID(void);
#define LibOrgBouncycastlePqcCryptoXmssBDSStateMap_serialVersionUID -3464451825208522308LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, serialVersionUID, jlong)

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoXmssBDSStateMap_updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *self, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed);

@implementation LibOrgBouncycastlePqcCryptoXmssBDSStateMap

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)params
                                                               withLong:(jlong)globalIndex
                                                          withByteArray:(IOSByteArray *)publicSeed
                                                          withByteArray:(IOSByteArray *)secretKeySeed {
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
  return self;
}

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap:(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *)stateMap
               withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)params
                                                          withLong:(jlong)globalIndex
                                                     withByteArray:(IOSByteArray *)publicSeed
                                                     withByteArray:(IOSByteArray *)secretKeySeed {
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, stateMap, params, globalIndex, publicSeed, secretKeySeed);
  return self;
}

- (void)updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *)params
                                                              withLong:(jlong)globalIndex
                                                         withByteArray:(IOSByteArray *)publicSeed
                                                         withByteArray:(IOSByteArray *)secretKeySeed {
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap_updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
}

- (jboolean)isEmpty {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) isEmpty];
}

- (LibOrgBouncycastlePqcCryptoXmssBDS *)getWithInt:(jint)index {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(index)];
}

- (LibOrgBouncycastlePqcCryptoXmssBDS *)updateWithInt:(jint)index
                                        withByteArray:(IOSByteArray *)publicSeed
                                        withByteArray:(IOSByteArray *)secretKeySeed
    withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:(LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress {
  return [((id<JavaUtilMap>) nil_chk(bdsState_)) putWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(index) withId:[((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk([bdsState_ getWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(index)])) getNextStateWithByteArray:publicSeed withByteArray:secretKeySeed withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:otsHashAddress]];
}

- (void)putWithInt:(jint)index
withLibOrgBouncycastlePqcCryptoXmssBDS:(LibOrgBouncycastlePqcCryptoXmssBDS *)bds {
  (void) [((id<JavaUtilMap>) nil_chk(bdsState_)) putWithId:LibOrgBouncycastleUtilIntegers_valueOfWithInt_(index) withId:bds];
}

- (LibOrgBouncycastlePqcCryptoXmssBDSStateMap *)withWOTSDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestName {
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap *newStateMap = new_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_init();
  for (id<JavaUtilIterator> keys = [((id<JavaUtilSet>) nil_chk([((id<JavaUtilMap>) nil_chk(bdsState_)) keySet])) iterator]; [((id<JavaUtilIterator>) nil_chk(keys)) hasNext]; ) {
    JavaLangInteger *key = [keys next];
    (void) [newStateMap->bdsState_ putWithId:key withId:[((LibOrgBouncycastlePqcCryptoXmssBDS *) nil_chk([bdsState_ getWithId:key])) withWOTSDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:digestName]];
  }
  return newStateMap;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssBDS;", 0x0, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssBDS;", 0x0, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 7, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssBDSStateMap;", 0x1, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap:withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[3].selector = @selector(updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters:withLong:withByteArray:withByteArray:);
  methods[4].selector = @selector(isEmpty);
  methods[5].selector = @selector(getWithInt:);
  methods[6].selector = @selector(updateWithInt:withByteArray:withByteArray:withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:);
  methods[7].selector = @selector(putWithInt:withLibOrgBouncycastlePqcCryptoXmssBDS:);
  methods[8].selector = @selector(withWOTSDigestWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastlePqcCryptoXmssBDSStateMap_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "bdsState_", "LJavaUtilMap;", .constantValue.asLong = 0, 0x12, -1, -1, 11, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters;J[B[B", "LLibOrgBouncycastlePqcCryptoXmssBDSStateMap;LLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters;J[B[B", "updateState", "get", "I", "update", "I[B[BLLibOrgBouncycastlePqcCryptoXmssOTSHashAddress;", "put", "ILLibOrgBouncycastlePqcCryptoXmssBDS;", "withWOTSDigest", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "Ljava/util/Map<Ljava/lang/Integer;Llib/org/bouncycastle/pqc/crypto/xmss/BDS;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssBDSStateMap = { "BDSStateMap", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x1, 9, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssBDSStateMap;
}

@end

void LibOrgBouncycastlePqcCryptoXmssBDSStateMap_init(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *self) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *new_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, init)
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *create_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, init)
}

void LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *self, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
  for (jlong index = 0; index < globalIndex; index++) {
    LibOrgBouncycastlePqcCryptoXmssBDSStateMap_updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, index, publicSeed, secretKeySeed);
  }
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *new_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, params, globalIndex, publicSeed, secretKeySeed)
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *create_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, initWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, params, globalIndex, publicSeed, secretKeySeed)
}

void LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *self, LibOrgBouncycastlePqcCryptoXmssBDSStateMap *stateMap, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  NSObject_init(self);
  self->bdsState_ = new_JavaUtilTreeMap_init();
  for (id<JavaUtilIterator> it = [((id<JavaUtilSet>) nil_chk([((LibOrgBouncycastlePqcCryptoXmssBDSStateMap *) nil_chk(stateMap))->bdsState_ keySet])) iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    JavaLangInteger *key = (JavaLangInteger *) cast_chk([it next], [JavaLangInteger class]);
    (void) [self->bdsState_ putWithId:key withId:[stateMap->bdsState_ getWithId:key]];
  }
  LibOrgBouncycastlePqcCryptoXmssBDSStateMap_updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(self, params, globalIndex, publicSeed, secretKeySeed);
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *new_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *stateMap, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, stateMap, params, globalIndex, publicSeed, secretKeySeed)
}

LibOrgBouncycastlePqcCryptoXmssBDSStateMap *create_LibOrgBouncycastlePqcCryptoXmssBDSStateMap_initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *stateMap, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssBDSStateMap, initWithLibOrgBouncycastlePqcCryptoXmssBDSStateMap_withLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_, stateMap, params, globalIndex, publicSeed, secretKeySeed)
}

void LibOrgBouncycastlePqcCryptoXmssBDSStateMap_updateStateWithLibOrgBouncycastlePqcCryptoXmssXMSSMTParameters_withLong_withByteArray_withByteArray_(LibOrgBouncycastlePqcCryptoXmssBDSStateMap *self, LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *params, jlong globalIndex, IOSByteArray *publicSeed, IOSByteArray *secretKeySeed) {
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *xmssParams = [((LibOrgBouncycastlePqcCryptoXmssXMSSMTParameters *) nil_chk(params)) getXMSSParameters];
  jint xmssHeight = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(xmssParams)) getHeight];
  jlong indexTree = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(globalIndex, xmssHeight);
  jint indexLeaf = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(globalIndex, xmssHeight);
  LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *otsHashAddress = (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init() withTreeAddressWithLong:indexTree])) withOTSAddressWithInt:indexLeaf])) build], [LibOrgBouncycastlePqcCryptoXmssOTSHashAddress class]);
  if (indexLeaf < ((JreLShift32(1, xmssHeight)) - 1)) {
    if ([self getWithInt:0] == nil || indexLeaf == 0) {
      [self putWithInt:0 withLibOrgBouncycastlePqcCryptoXmssBDS:new_LibOrgBouncycastlePqcCryptoXmssBDS_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_withByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress_(xmssParams, publicSeed, secretKeySeed, otsHashAddress)];
    }
    (void) [self updateWithInt:0 withByteArray:publicSeed withByteArray:secretKeySeed withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:otsHashAddress];
  }
  for (jint layer = 1; layer < [params getLayers]; layer++) {
    indexLeaf = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_getLeafIndexWithLong_withInt_(indexTree, xmssHeight);
    indexTree = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_getTreeIndexWithLong_withInt_(indexTree, xmssHeight);
    otsHashAddress = (LibOrgBouncycastlePqcCryptoXmssOTSHashAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssOTSHashAddress_Builder_init() withLayerAddressWithInt:layer])) withTreeAddressWithLong:indexTree])) withOTSAddressWithInt:indexLeaf])) build], [LibOrgBouncycastlePqcCryptoXmssOTSHashAddress class]);
    if (indexLeaf < ((JreLShift32(1, xmssHeight)) - 1) && LibOrgBouncycastlePqcCryptoXmssXMSSUtil_isNewAuthenticationPathNeededWithLong_withInt_withInt_(globalIndex, xmssHeight, layer)) {
      if ([self getWithInt:layer] == nil) {
        [self putWithInt:layer withLibOrgBouncycastlePqcCryptoXmssBDS:new_LibOrgBouncycastlePqcCryptoXmssBDS_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_withByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress_([params getXMSSParameters], publicSeed, secretKeySeed, otsHashAddress)];
      }
      (void) [self updateWithInt:layer withByteArray:publicSeed withByteArray:secretKeySeed withLibOrgBouncycastlePqcCryptoXmssOTSHashAddress:otsHashAddress];
    }
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssBDSStateMap)