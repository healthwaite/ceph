// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <string>

#include "crimson/common/errorator.h"
#include "crimson/os/seastore/cached_extent.h"
#include "crimson/os/seastore/seastore_types.h"
#include "crimson/os/seastore/transaction.h"

namespace crimson::os::seastore::onode {

using crimson::os::seastore::Transaction;
using crimson::os::seastore::TransactionRef;
using crimson::os::seastore::make_transaction;
using crimson::os::seastore::laddr_t;
using crimson::os::seastore::L_ADDR_MIN;
using crimson::os::seastore::L_ADDR_NULL;
using crimson::os::seastore::extent_len_t;

class NodeExtent;
class NodeExtentManager;
class RootNodeTracker;
using NodeExtentRef = crimson::os::seastore::TCachedExtentRef<NodeExtent>;
using NodeExtentManagerURef = std::unique_ptr<NodeExtentManager>;
using RootNodeTrackerURef = std::unique_ptr<RootNodeTracker>;
struct context_t {
  NodeExtentManager& nm;
  Transaction& t;
};

class LeafNodeImpl;
class InternalNodeImpl;
class NodeImpl;
using LeafNodeImplURef = std::unique_ptr<LeafNodeImpl>;
using InternalNodeImplURef = std::unique_ptr<InternalNodeImpl>;
using NodeImplURef = std::unique_ptr<NodeImpl>;

using level_t = uint8_t;
constexpr auto INDEX_END = std::numeric_limits<size_t>::max();
constexpr auto INDEX_LAST = INDEX_END - 0xf;
constexpr auto INDEX_UPPER_BOUND = INDEX_END - 0xff;
inline bool is_valid_index(size_t index) { return index < INDEX_UPPER_BOUND; }

// TODO: decide by NODE_BLOCK_SIZE
using node_offset_t = uint16_t;
constexpr node_offset_t DISK_BLOCK_SIZE = 1u << 12;
constexpr node_offset_t NODE_BLOCK_SIZE = DISK_BLOCK_SIZE * 1u;

enum class MatchKindBS : int8_t { NE = -1, EQ = 0 };

enum class MatchKindCMP : int8_t { NE = -1, EQ = 0, PO };
inline MatchKindCMP toMatchKindCMP(int value) {
  if (value > 0) {
    return MatchKindCMP::PO;
  } else if (value < 0) {
    return MatchKindCMP::NE;
  } else {
    return MatchKindCMP::EQ;
  }
}
template <typename Type>
MatchKindCMP toMatchKindCMP(const Type& l, const Type& r) {
  int match = l - r;
  return toMatchKindCMP(match);
}

template <>
inline MatchKindCMP toMatchKindCMP<std::string>(
    const std::string& l, const std::string& r) {
  return toMatchKindCMP(l.compare(r));
}

inline MatchKindCMP toMatchKindCMP(
    const char* l, size_t l_len, const char* r, size_t r_len) {
  assert(l && l_len);
  assert(r && r_len);
  auto min_len = std::min(l_len, r_len);
  auto match = toMatchKindCMP(std::strncmp(l, r, min_len));
  if (match == MatchKindCMP::EQ) {
    return toMatchKindCMP(l_len, r_len);
  } else {
    return match;
  }
}

inline MatchKindCMP toMatchKindCMP(
    const std::string& l, const char* r, size_t r_len) {
  assert(r && r_len);
  return toMatchKindCMP(l.compare(0u, l.length(), r, r_len));
}

inline MatchKindCMP toMatchKindCMP(
    const char* l, size_t l_len, const std::string& r) {
  assert(l && l_len);
  return toMatchKindCMP(-r.compare(0u, r.length(), l, l_len));
}

inline MatchKindCMP reverse(MatchKindCMP cmp) {
  if (cmp == MatchKindCMP::NE) {
    return MatchKindCMP::PO;
  } else if (cmp == MatchKindCMP::PO) {
    return MatchKindCMP::NE;
  } else {
    return cmp;
  }
}

}
