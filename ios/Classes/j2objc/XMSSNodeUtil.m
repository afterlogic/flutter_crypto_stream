//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSNodeUtil.java
//

#include "HashTreeAddress.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyedHashFunctions.h"
#include "LTreeAddress.h"
#include "WOTSPlus.h"
#include "WOTSPlusParameters.h"
#include "WOTSPlusPublicKeyParameters.h"
#include "XMSSAddress.h"
#include "XMSSNode.h"
#include "XMSSNodeUtil.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Math.h"
#include "java/lang/NullPointerException.h"

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastlePqcCryptoXmssXMSSNode *)lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                               withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *)publicKey
                                              withLibOrgBouncycastlePqcCryptoXmssLTreeAddress:(LibOrgBouncycastlePqcCryptoXmssLTreeAddress *)address {
  return LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_withLibOrgBouncycastlePqcCryptoXmssLTreeAddress_(wotsPlus, publicKey, address);
}

+ (LibOrgBouncycastlePqcCryptoXmssXMSSNode *)randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                                                          withLibOrgBouncycastlePqcCryptoXmssXMSSNode:(LibOrgBouncycastlePqcCryptoXmssXMSSNode *)left
                                                          withLibOrgBouncycastlePqcCryptoXmssXMSSNode:(LibOrgBouncycastlePqcCryptoXmssXMSSNode *)right
                                                       withLibOrgBouncycastlePqcCryptoXmssXMSSAddress:(LibOrgBouncycastlePqcCryptoXmssXMSSAddress *)address {
  return LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSAddress_(wotsPlus, left, right, address);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSNode;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSNode;", 0x8, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters:withLibOrgBouncycastlePqcCryptoXmssLTreeAddress:);
  methods[2].selector = @selector(randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus:withLibOrgBouncycastlePqcCryptoXmssXMSSNode:withLibOrgBouncycastlePqcCryptoXmssXMSSNode:withLibOrgBouncycastlePqcCryptoXmssXMSSAddress:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "lTree", "LLibOrgBouncycastlePqcCryptoXmssWOTSPlus;LLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters;LLibOrgBouncycastlePqcCryptoXmssLTreeAddress;", "randomizeHash", "LLibOrgBouncycastlePqcCryptoXmssWOTSPlus;LLibOrgBouncycastlePqcCryptoXmssXMSSNode;LLibOrgBouncycastlePqcCryptoXmssXMSSNode;LLibOrgBouncycastlePqcCryptoXmssXMSSAddress;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil = { "XMSSNodeUtil", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, NULL, 7, 0x0, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *new_LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil, init)
}

LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil *create_LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil, init)
}

LibOrgBouncycastlePqcCryptoXmssXMSSNode *LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_lTreeWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters_withLibOrgBouncycastlePqcCryptoXmssLTreeAddress_(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *wotsPlus, LibOrgBouncycastlePqcCryptoXmssWOTSPlusPublicKeyParameters *publicKey, LibOrgBouncycastlePqcCryptoXmssLTreeAddress *address) {
  LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_initialize();
  if (publicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicKey == null");
  }
  if (address == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"address == null");
  }
  jint len = [((LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssWOTSPlus *) nil_chk(wotsPlus)) getParams])) getLen];
  IOSObjectArray *publicKeyBytes = [publicKey toByteArray];
  IOSObjectArray *publicKeyNodes = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(publicKeyBytes))->size_ type:LibOrgBouncycastlePqcCryptoXmssXMSSNode_class_()];
  for (jint i = 0; i < publicKeyBytes->size_; i++) {
    (void) IOSObjectArray_SetAndConsume(publicKeyNodes, i, new_LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_(0, IOSObjectArray_Get(publicKeyBytes, i)));
  }
  address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[address getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:0])) withTreeIndexWithInt:[address getTreeIndex]])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
  while (len > 1) {
    for (jint i = 0; i < JreFpToInt(JavaLangMath_floorWithDouble_(len / 2)); i++) {
      address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[((LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) nil_chk(address)) getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:[address getTreeHeight]])) withTreeIndexWithInt:i])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
      (void) IOSObjectArray_Set(publicKeyNodes, i, LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSAddress_(wotsPlus, IOSObjectArray_Get(publicKeyNodes, 2 * i), IOSObjectArray_Get(publicKeyNodes, (2 * i) + 1), address));
    }
    if (len % 2 == 1) {
      (void) IOSObjectArray_Set(publicKeyNodes, JreFpToInt(JavaLangMath_floorWithDouble_(len / 2)), IOSObjectArray_Get(publicKeyNodes, len - 1));
    }
    len = JreFpToInt(JavaLangMath_ceilWithDouble_((jdouble) len / 2));
    address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[((LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) nil_chk(address)) getLayerAddress]])) withTreeAddressWithLong:[address getTreeAddress]])) withLTreeAddressWithInt:[address getLTreeAddress]])) withTreeHeightWithInt:[address getTreeHeight] + 1])) withTreeIndexWithInt:[address getTreeIndex]])) withKeyAndMaskWithInt:[address getKeyAndMask]])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
  }
  return IOSObjectArray_Get(publicKeyNodes, 0);
}

LibOrgBouncycastlePqcCryptoXmssXMSSNode *LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_randomizeHashWithLibOrgBouncycastlePqcCryptoXmssWOTSPlus_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSNode_withLibOrgBouncycastlePqcCryptoXmssXMSSAddress_(LibOrgBouncycastlePqcCryptoXmssWOTSPlus *wotsPlus, LibOrgBouncycastlePqcCryptoXmssXMSSNode *left, LibOrgBouncycastlePqcCryptoXmssXMSSNode *right, LibOrgBouncycastlePqcCryptoXmssXMSSAddress *address) {
  LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil_initialize();
  if (left == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"left == null");
  }
  if (right == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"right == null");
  }
  if ([left getHeight] != [right getHeight]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"height of both nodes must be equal");
  }
  if (address == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"address == null");
  }
  IOSByteArray *publicSeed = [((LibOrgBouncycastlePqcCryptoXmssWOTSPlus *) nil_chk(wotsPlus)) getPublicSeed];
  if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssLTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:0])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:0])) build], [LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *key = [((LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((LibOrgBouncycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssLTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:1])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:1])) build], [LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *bitmask0 = [((LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((LibOrgBouncycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssLTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssLTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssLTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withLTreeAddressWithInt:[tmpAddress getLTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:2])) build], [LibOrgBouncycastlePqcCryptoXmssLTreeAddress class]);
  }
  else if ([address isKindOfClass:[LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]]) {
    LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *tmpAddress = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) address;
    address = (LibOrgBouncycastlePqcCryptoXmssHashTreeAddress *) cast_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([((LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder *) nil_chk([new_LibOrgBouncycastlePqcCryptoXmssHashTreeAddress_Builder_init() withLayerAddressWithInt:[tmpAddress getLayerAddress]])) withTreeAddressWithLong:[tmpAddress getTreeAddress]])) withTreeHeightWithInt:[tmpAddress getTreeHeight]])) withTreeIndexWithInt:[tmpAddress getTreeIndex]])) withKeyAndMaskWithInt:2])) build], [LibOrgBouncycastlePqcCryptoXmssHashTreeAddress class]);
  }
  IOSByteArray *bitmask1 = [((LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) PRFWithByteArray:publicSeed withByteArray:[((LibOrgBouncycastlePqcCryptoXmssXMSSAddress *) nil_chk(address)) toByteArray]];
  jint n = [((LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *) nil_chk([wotsPlus getParams])) getDigestSize];
  IOSByteArray *tmpMask = [IOSByteArray newArrayWithLength:2 * n];
  for (jint i = 0; i < n; i++) {
    *IOSByteArray_GetRef(tmpMask, i) = (jbyte) (IOSByteArray_Get(nil_chk([left getValue]), i) ^ IOSByteArray_Get(nil_chk(bitmask0), i));
  }
  for (jint i = 0; i < n; i++) {
    *IOSByteArray_GetRef(tmpMask, i + n) = (jbyte) (IOSByteArray_Get(nil_chk([right getValue]), i) ^ IOSByteArray_Get(nil_chk(bitmask1), i));
  }
  IOSByteArray *out = [((LibOrgBouncycastlePqcCryptoXmssKeyedHashFunctions *) nil_chk([wotsPlus getKhf])) HWithByteArray:key withByteArray:tmpMask];
  return new_LibOrgBouncycastlePqcCryptoXmssXMSSNode_initWithInt_withByteArray_([left getHeight], out);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSNodeUtil)
