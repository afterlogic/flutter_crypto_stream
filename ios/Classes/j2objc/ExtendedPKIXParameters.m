//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/ExtendedPKIXParameters.java
//

#include "ExtendedPKIXParameters.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "PKIXAttrCertChecker.h"
#include "Selector.h"
#include "Store.h"
#include "X509CertStoreSelector.h"
#include "java/lang/ClassCastException.h"
#include "java/lang/Exception.h"
#include "java/lang/RuntimeException.h"
#include "java/security/cert/CertSelector.h"
#include "java/security/cert/CertStore.h"
#include "java/security/cert/PKIXParameters.h"
#include "java/security/cert/TrustAnchor.h"
#include "java/security/cert/X509CertSelector.h"
#include "java/util/ArrayList.h"
#include "java/util/Collections.h"
#include "java/util/Date.h"
#include "java/util/HashSet.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"
#include "java/util/Set.h"

@interface LibOrgBouncycastleX509ExtendedPKIXParameters () {
 @public
  id<JavaUtilList> stores_;
  id<LibOrgBouncycastleUtilSelector> selector_;
  jboolean additionalLocationsEnabled_;
  id<JavaUtilList> additionalStores_;
  id<JavaUtilSet> trustedACIssuers_;
  id<JavaUtilSet> necessaryACAttributes_;
  id<JavaUtilSet> prohibitedACAttributes_;
  id<JavaUtilSet> attrCertCheckers_;
  jint validityModel_;
  jboolean useDeltas_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, stores_, id<JavaUtilList>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, selector_, id<LibOrgBouncycastleUtilSelector>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, additionalStores_, id<JavaUtilList>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, trustedACIssuers_, id<JavaUtilSet>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, necessaryACAttributes_, id<JavaUtilSet>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, prohibitedACAttributes_, id<JavaUtilSet>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509ExtendedPKIXParameters, attrCertCheckers_, id<JavaUtilSet>)

@implementation LibOrgBouncycastleX509ExtendedPKIXParameters

+ (jint)PKIX_VALIDITY_MODEL {
  return LibOrgBouncycastleX509ExtendedPKIXParameters_PKIX_VALIDITY_MODEL;
}

+ (jint)CHAIN_VALIDITY_MODEL {
  return LibOrgBouncycastleX509ExtendedPKIXParameters_CHAIN_VALIDITY_MODEL;
}

- (instancetype)initWithJavaUtilSet:(id<JavaUtilSet>)trustAnchors {
  LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_(self, trustAnchors);
  return self;
}

+ (LibOrgBouncycastleX509ExtendedPKIXParameters *)getInstanceWithJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)pkixParams {
  return LibOrgBouncycastleX509ExtendedPKIXParameters_getInstanceWithJavaSecurityCertPKIXParameters_(pkixParams);
}

- (void)setParamsWithJavaSecurityCertPKIXParameters:(JavaSecurityCertPKIXParameters *)params {
  [self setDateWithJavaUtilDate:[((JavaSecurityCertPKIXParameters *) nil_chk(params)) getDate]];
  [self setCertPathCheckersWithJavaUtilList:[params getCertPathCheckers]];
  [self setCertStoresWithJavaUtilList:[params getCertStores]];
  [self setAnyPolicyInhibitedWithBoolean:[params isAnyPolicyInhibited]];
  [self setExplicitPolicyRequiredWithBoolean:[params isExplicitPolicyRequired]];
  [self setPolicyMappingInhibitedWithBoolean:[params isPolicyMappingInhibited]];
  [self setRevocationEnabledWithBoolean:[params isRevocationEnabled]];
  [self setInitialPoliciesWithJavaUtilSet:[params getInitialPolicies]];
  [self setPolicyQualifiersRejectedWithBoolean:[params getPolicyQualifiersRejected]];
  [self setSigProviderWithNSString:[params getSigProvider]];
  [self setTargetCertConstraintsWithJavaSecurityCertCertSelector:[params getTargetCertConstraints]];
  @try {
    [self setTrustAnchorsWithJavaUtilSet:[params getTrustAnchors]];
  }
  @catch (JavaLangException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_([e getMessage]);
  }
  if ([params isKindOfClass:[LibOrgBouncycastleX509ExtendedPKIXParameters class]]) {
    LibOrgBouncycastleX509ExtendedPKIXParameters *_params = (LibOrgBouncycastleX509ExtendedPKIXParameters *) params;
    validityModel_ = _params->validityModel_;
    useDeltas_ = _params->useDeltas_;
    additionalLocationsEnabled_ = _params->additionalLocationsEnabled_;
    selector_ = _params->selector_ == nil ? nil : (id<LibOrgBouncycastleUtilSelector>) cast_check([_params->selector_ clone], LibOrgBouncycastleUtilSelector_class_());
    stores_ = new_JavaUtilArrayList_initWithJavaUtilCollection_(_params->stores_);
    additionalStores_ = new_JavaUtilArrayList_initWithJavaUtilCollection_(_params->additionalStores_);
    trustedACIssuers_ = new_JavaUtilHashSet_initWithJavaUtilCollection_(_params->trustedACIssuers_);
    prohibitedACAttributes_ = new_JavaUtilHashSet_initWithJavaUtilCollection_(_params->prohibitedACAttributes_);
    necessaryACAttributes_ = new_JavaUtilHashSet_initWithJavaUtilCollection_(_params->necessaryACAttributes_);
    attrCertCheckers_ = new_JavaUtilHashSet_initWithJavaUtilCollection_(_params->attrCertCheckers_);
  }
}

- (jboolean)isUseDeltasEnabled {
  return useDeltas_;
}

- (void)setUseDeltasEnabledWithBoolean:(jboolean)useDeltas {
  self->useDeltas_ = useDeltas;
}

- (jint)getValidityModel {
  return validityModel_;
}

- (void)setCertStoresWithJavaUtilList:(id<JavaUtilList>)stores {
  if (stores != nil) {
    id<JavaUtilIterator> it = [stores iterator];
    while ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
      [self addCertStoreWithJavaSecurityCertCertStore:(JavaSecurityCertCertStore *) cast_chk([it next], [JavaSecurityCertCertStore class])];
    }
  }
}

- (void)setStoresWithJavaUtilList:(id<JavaUtilList>)stores {
  if (stores == nil) {
    self->stores_ = new_JavaUtilArrayList_init();
  }
  else {
    for (id<JavaUtilIterator> i = [stores iterator]; [((id<JavaUtilIterator>) nil_chk(i)) hasNext]; ) {
      if (!([LibOrgBouncycastleUtilStore_class_() isInstance:[i next]])) {
        @throw new_JavaLangClassCastException_initWithNSString_(@"All elements of list must be of type lib.org.bouncycastle.util.Store.");
      }
    }
    self->stores_ = new_JavaUtilArrayList_initWithJavaUtilCollection_(stores);
  }
}

- (void)addStoreWithLibOrgBouncycastleUtilStore:(id<LibOrgBouncycastleUtilStore>)store {
  if (store != nil) {
    [((id<JavaUtilList>) nil_chk(stores_)) addWithId:store];
  }
}

- (void)addAdditionalStoreWithLibOrgBouncycastleUtilStore:(id<LibOrgBouncycastleUtilStore>)store {
  if (store != nil) {
    [((id<JavaUtilList>) nil_chk(additionalStores_)) addWithId:store];
  }
}

- (void)addAddionalStoreWithLibOrgBouncycastleUtilStore:(id<LibOrgBouncycastleUtilStore>)store {
  [self addAdditionalStoreWithLibOrgBouncycastleUtilStore:store];
}

- (id<JavaUtilList>)getAdditionalStores {
  return JavaUtilCollections_unmodifiableListWithJavaUtilList_(additionalStores_);
}

- (id<JavaUtilList>)getStores {
  return JavaUtilCollections_unmodifiableListWithJavaUtilList_(new_JavaUtilArrayList_initWithJavaUtilCollection_(stores_));
}

- (void)setValidityModelWithInt:(jint)validityModel {
  self->validityModel_ = validityModel;
}

- (id)java_clone {
  LibOrgBouncycastleX509ExtendedPKIXParameters *params;
  @try {
    params = new_LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_([self getTrustAnchors]);
  }
  @catch (JavaLangException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_([e getMessage]);
  }
  [((LibOrgBouncycastleX509ExtendedPKIXParameters *) nil_chk(params)) setParamsWithJavaSecurityCertPKIXParameters:self];
  return params;
}

- (jboolean)isAdditionalLocationsEnabled {
  return additionalLocationsEnabled_;
}

- (void)setAdditionalLocationsEnabledWithBoolean:(jboolean)enabled {
  additionalLocationsEnabled_ = enabled;
}

- (id<LibOrgBouncycastleUtilSelector>)getTargetConstraints {
  if (selector_ != nil) {
    return (id<LibOrgBouncycastleUtilSelector>) cast_check([selector_ clone], LibOrgBouncycastleUtilSelector_class_());
  }
  else {
    return nil;
  }
}

- (void)setTargetConstraintsWithLibOrgBouncycastleUtilSelector:(id<LibOrgBouncycastleUtilSelector>)selector {
  if (selector != nil) {
    self->selector_ = (id<LibOrgBouncycastleUtilSelector>) cast_check([selector clone], LibOrgBouncycastleUtilSelector_class_());
  }
  else {
    self->selector_ = nil;
  }
}

- (void)setTargetCertConstraintsWithJavaSecurityCertCertSelector:(id<JavaSecurityCertCertSelector>)selector {
  [super setTargetCertConstraintsWithJavaSecurityCertCertSelector:selector];
  if (selector != nil) {
    self->selector_ = LibOrgBouncycastleX509X509CertStoreSelector_getInstanceWithJavaSecurityCertX509CertSelector_((JavaSecurityCertX509CertSelector *) cast_chk(selector, [JavaSecurityCertX509CertSelector class]));
  }
  else {
    self->selector_ = nil;
  }
}

- (id<JavaUtilSet>)getTrustedACIssuers {
  return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(trustedACIssuers_);
}

- (void)setTrustedACIssuersWithJavaUtilSet:(id<JavaUtilSet>)trustedACIssuers {
  if (trustedACIssuers == nil) {
    [((id<JavaUtilSet>) nil_chk(self->trustedACIssuers_)) clear];
    return;
  }
  for (id<JavaUtilIterator> it = [trustedACIssuers iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    if (!([[it next] isKindOfClass:[JavaSecurityCertTrustAnchor class]])) {
      @throw new_JavaLangClassCastException_initWithNSString_(JreStrcat("$$C", @"All elements of set must be of type ", [JavaSecurityCertTrustAnchor_class_() getName], '.'));
    }
  }
  [((id<JavaUtilSet>) nil_chk(self->trustedACIssuers_)) clear];
  [((id<JavaUtilSet>) nil_chk(self->trustedACIssuers_)) addAllWithJavaUtilCollection:trustedACIssuers];
}

- (id<JavaUtilSet>)getNecessaryACAttributes {
  return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(necessaryACAttributes_);
}

- (void)setNecessaryACAttributesWithJavaUtilSet:(id<JavaUtilSet>)necessaryACAttributes {
  if (necessaryACAttributes == nil) {
    [((id<JavaUtilSet>) nil_chk(self->necessaryACAttributes_)) clear];
    return;
  }
  for (id<JavaUtilIterator> it = [necessaryACAttributes iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    if (!([[it next] isKindOfClass:[NSString class]])) {
      @throw new_JavaLangClassCastException_initWithNSString_(@"All elements of set must be of type String.");
    }
  }
  [((id<JavaUtilSet>) nil_chk(self->necessaryACAttributes_)) clear];
  [((id<JavaUtilSet>) nil_chk(self->necessaryACAttributes_)) addAllWithJavaUtilCollection:necessaryACAttributes];
}

- (id<JavaUtilSet>)getProhibitedACAttributes {
  return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(prohibitedACAttributes_);
}

- (void)setProhibitedACAttributesWithJavaUtilSet:(id<JavaUtilSet>)prohibitedACAttributes {
  if (prohibitedACAttributes == nil) {
    [((id<JavaUtilSet>) nil_chk(self->prohibitedACAttributes_)) clear];
    return;
  }
  for (id<JavaUtilIterator> it = [prohibitedACAttributes iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    if (!([[it next] isKindOfClass:[NSString class]])) {
      @throw new_JavaLangClassCastException_initWithNSString_(@"All elements of set must be of type String.");
    }
  }
  [((id<JavaUtilSet>) nil_chk(self->prohibitedACAttributes_)) clear];
  [((id<JavaUtilSet>) nil_chk(self->prohibitedACAttributes_)) addAllWithJavaUtilCollection:prohibitedACAttributes];
}

- (id<JavaUtilSet>)getAttrCertCheckers {
  return JavaUtilCollections_unmodifiableSetWithJavaUtilSet_(attrCertCheckers_);
}

- (void)setAttrCertCheckersWithJavaUtilSet:(id<JavaUtilSet>)attrCertCheckers {
  if (attrCertCheckers == nil) {
    [((id<JavaUtilSet>) nil_chk(self->attrCertCheckers_)) clear];
    return;
  }
  for (id<JavaUtilIterator> it = [attrCertCheckers iterator]; [((id<JavaUtilIterator>) nil_chk(it)) hasNext]; ) {
    if (!([[it next] isKindOfClass:[LibOrgBouncycastleX509PKIXAttrCertChecker class]])) {
      @throw new_JavaLangClassCastException_initWithNSString_(JreStrcat("$$C", @"All elements of set must be of type ", [LibOrgBouncycastleX509PKIXAttrCertChecker_class_() getName], '.'));
    }
  }
  [((id<JavaUtilSet>) nil_chk(self->attrCertCheckers_)) clear];
  [((id<JavaUtilSet>) nil_chk(self->attrCertCheckers_)) addAllWithJavaUtilCollection:attrCertCheckers];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleX509ExtendedPKIXParameters;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 13, 11, -1, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 14, 15, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 16, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 17, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleUtilSelector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 18, 19, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 20, 21, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 22, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 23, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 24, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 25, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaUtilSet:);
  methods[1].selector = @selector(getInstanceWithJavaSecurityCertPKIXParameters:);
  methods[2].selector = @selector(setParamsWithJavaSecurityCertPKIXParameters:);
  methods[3].selector = @selector(isUseDeltasEnabled);
  methods[4].selector = @selector(setUseDeltasEnabledWithBoolean:);
  methods[5].selector = @selector(getValidityModel);
  methods[6].selector = @selector(setCertStoresWithJavaUtilList:);
  methods[7].selector = @selector(setStoresWithJavaUtilList:);
  methods[8].selector = @selector(addStoreWithLibOrgBouncycastleUtilStore:);
  methods[9].selector = @selector(addAdditionalStoreWithLibOrgBouncycastleUtilStore:);
  methods[10].selector = @selector(addAddionalStoreWithLibOrgBouncycastleUtilStore:);
  methods[11].selector = @selector(getAdditionalStores);
  methods[12].selector = @selector(getStores);
  methods[13].selector = @selector(setValidityModelWithInt:);
  methods[14].selector = @selector(java_clone);
  methods[15].selector = @selector(isAdditionalLocationsEnabled);
  methods[16].selector = @selector(setAdditionalLocationsEnabledWithBoolean:);
  methods[17].selector = @selector(getTargetConstraints);
  methods[18].selector = @selector(setTargetConstraintsWithLibOrgBouncycastleUtilSelector:);
  methods[19].selector = @selector(setTargetCertConstraintsWithJavaSecurityCertCertSelector:);
  methods[20].selector = @selector(getTrustedACIssuers);
  methods[21].selector = @selector(setTrustedACIssuersWithJavaUtilSet:);
  methods[22].selector = @selector(getNecessaryACAttributes);
  methods[23].selector = @selector(setNecessaryACAttributesWithJavaUtilSet:);
  methods[24].selector = @selector(getProhibitedACAttributes);
  methods[25].selector = @selector(setProhibitedACAttributesWithJavaUtilSet:);
  methods[26].selector = @selector(getAttrCertCheckers);
  methods[27].selector = @selector(setAttrCertCheckersWithJavaUtilSet:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "stores_", "LJavaUtilList;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "selector_", "LLibOrgBouncycastleUtilSelector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "additionalLocationsEnabled_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "additionalStores_", "LJavaUtilList;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "trustedACIssuers_", "LJavaUtilSet;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "necessaryACAttributes_", "LJavaUtilSet;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "prohibitedACAttributes_", "LJavaUtilSet;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "attrCertCheckers_", "LJavaUtilSet;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "PKIX_VALIDITY_MODEL", "I", .constantValue.asInt = LibOrgBouncycastleX509ExtendedPKIXParameters_PKIX_VALIDITY_MODEL, 0x19, -1, -1, -1, -1 },
    { "CHAIN_VALIDITY_MODEL", "I", .constantValue.asInt = LibOrgBouncycastleX509ExtendedPKIXParameters_CHAIN_VALIDITY_MODEL, 0x19, -1, -1, -1, -1 },
    { "validityModel_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "useDeltas_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilSet;", "LJavaSecurityInvalidAlgorithmParameterException;", "getInstance", "LJavaSecurityCertPKIXParameters;", "setParams", "setUseDeltasEnabled", "Z", "setCertStores", "LJavaUtilList;", "setStores", "addStore", "LLibOrgBouncycastleUtilStore;", "addAdditionalStore", "addAddionalStore", "setValidityModel", "I", "clone", "setAdditionalLocationsEnabled", "setTargetConstraints", "LLibOrgBouncycastleUtilSelector;", "setTargetCertConstraints", "LJavaSecurityCertCertSelector;", "setTrustedACIssuers", "setNecessaryACAttributes", "setProhibitedACAttributes", "setAttrCertCheckers" };
  static const J2ObjcClassInfo _LibOrgBouncycastleX509ExtendedPKIXParameters = { "ExtendedPKIXParameters", "lib.org.bouncycastle.x509", ptrTable, methods, fields, 7, 0x1, 28, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleX509ExtendedPKIXParameters;
}

@end

void LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_(LibOrgBouncycastleX509ExtendedPKIXParameters *self, id<JavaUtilSet> trustAnchors) {
  JavaSecurityCertPKIXParameters_initWithJavaUtilSet_(self, trustAnchors);
  self->validityModel_ = LibOrgBouncycastleX509ExtendedPKIXParameters_PKIX_VALIDITY_MODEL;
  self->useDeltas_ = false;
  self->stores_ = new_JavaUtilArrayList_init();
  self->additionalStores_ = new_JavaUtilArrayList_init();
  self->trustedACIssuers_ = new_JavaUtilHashSet_init();
  self->necessaryACAttributes_ = new_JavaUtilHashSet_init();
  self->prohibitedACAttributes_ = new_JavaUtilHashSet_init();
  self->attrCertCheckers_ = new_JavaUtilHashSet_init();
}

LibOrgBouncycastleX509ExtendedPKIXParameters *new_LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_(id<JavaUtilSet> trustAnchors) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509ExtendedPKIXParameters, initWithJavaUtilSet_, trustAnchors)
}

LibOrgBouncycastleX509ExtendedPKIXParameters *create_LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_(id<JavaUtilSet> trustAnchors) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509ExtendedPKIXParameters, initWithJavaUtilSet_, trustAnchors)
}

LibOrgBouncycastleX509ExtendedPKIXParameters *LibOrgBouncycastleX509ExtendedPKIXParameters_getInstanceWithJavaSecurityCertPKIXParameters_(JavaSecurityCertPKIXParameters *pkixParams) {
  LibOrgBouncycastleX509ExtendedPKIXParameters_initialize();
  LibOrgBouncycastleX509ExtendedPKIXParameters *params;
  @try {
    params = new_LibOrgBouncycastleX509ExtendedPKIXParameters_initWithJavaUtilSet_([((JavaSecurityCertPKIXParameters *) nil_chk(pkixParams)) getTrustAnchors]);
  }
  @catch (JavaLangException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_([e getMessage]);
  }
  [((LibOrgBouncycastleX509ExtendedPKIXParameters *) nil_chk(params)) setParamsWithJavaSecurityCertPKIXParameters:pkixParams];
  return params;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleX509ExtendedPKIXParameters)
