//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/CollectionStore.java
//

#ifndef CollectionStore_H
#define CollectionStore_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Iterable.h"
#include "J2ObjC_header.h"
#include "Store.h"

@protocol JavaUtilCollection;
@protocol JavaUtilFunctionConsumer;
@protocol JavaUtilIterator;
@protocol JavaUtilSpliterator;
@protocol LibOrgBouncycastleUtilSelector;

@interface LibOrgBouncycastleUtilCollectionStore : NSObject < LibOrgBouncycastleUtilStore, LibOrgBouncycastleUtilIterable >

#pragma mark Public

- (instancetype __nonnull)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection;

- (id<JavaUtilCollection>)getMatchesWithLibOrgBouncycastleUtilSelector:(id<LibOrgBouncycastleUtilSelector>)selector;

- (id<JavaUtilIterator>)iterator;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilCollectionStore)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilCollectionStore_initWithJavaUtilCollection_(LibOrgBouncycastleUtilCollectionStore *self, id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleUtilCollectionStore *new_LibOrgBouncycastleUtilCollectionStore_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilCollectionStore *create_LibOrgBouncycastleUtilCollectionStore_initWithJavaUtilCollection_(id<JavaUtilCollection> collection);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilCollectionStore)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CollectionStore_H
