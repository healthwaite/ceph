// -*- mode:C++; tab-width:8; c-basic-offset:2;
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

// Async PUT: put_object_a and its sync wrapper, the non-batched paths
// (put_single_a, put_storage_a / put_phase3_a), put_finalize_a, and the
// batcher (BatchCommitQueue with one run_batch coroutine per batch).
//
// Keys, values, phases, statistics and fault-injection points are those of the
// previous thread-and-polling implementation; only the waiting changed.

#include "service_impl.hpp"

#include "admin_server.hpp"
#include "async/sync_wait.hpp"
#include "bucket_policy.hpp"
#include "constants.hpp"
#include "error_codes.hpp"
#include "gc_value.hpp"
#include "keys.hpp"
#include "kv_store.hpp"
#include "multipart_value.hpp"
#include "object_value.hpp"
#include "tier_config_state.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <openssl/evp.h>

using namespace std::chrono;

namespace kvrgw {

namespace {

// The single-part children that accompany the :O: value, built on the stack
// straight from the caller's buffers: C:E (spilled metadata, plus the body for
// kFlagDataInChildE) and C:D (body above max_inline).
void write_single_part_children(KvTransaction &tr,
                                const KvRgwServiceImpl::PutInTxnParams &p)
{
  const ObjectValueHeader &h = p.value.hdr;
  if (h.flags & kFlagExternalMetadata) {
    ChildEValue ce;
    ce.metadata_frame = p.metadata;
    if (h.flags & kFlagDataInChildE) {
      ce.tail = p.data;
    }
    const ChildValueBuf buf(ce);
    KeyBuf e_key;
    make_child_key(p.bucket_id, h.ref_tag.view(), kChildTypeExtended, e_key);
    tr.kv_put(e_key.view(), buf.value());
  }
  if (h.chunk_type == CHUNK_CHILD_D) {
    const uint8_t st = d_size_tier_from_size(p.data.size());
    KeyBuf d_key;
    make_d_key(p.bucket_id, st, h.ref_tag.view(), h.last_modified_sec, d_key);
    const ChildValueBuf buf(ChildValueHeader{}, p.data);
    tr.kv_put(d_key.view(), buf.value());
  }
}

void atomic_min(std::atomic<int64_t> &a, int64_t v)
{
  auto cur = a.load(std::memory_order_relaxed);
  while ((cur == 0 || v < cur) && !a.compare_exchange_weak(cur, v)) {
  }
}

void atomic_max(std::atomic<int64_t> &a, int64_t v)
{
  auto cur = a.load(std::memory_order_relaxed);
  while (v > cur && !a.compare_exchange_weak(cur, v)) {
  }
}

}  // namespace

// ===========================================================================
// put_finalize_a / put_in_txn_a
// ===========================================================================

async::Task<KvrgwErrorCode>
KvRgwServiceImpl::put_finalize_a(KvTransaction &tr, PutContext &ctx,
                                 PutInTxnParams &params, VerifiedBucket *verified,
                                 int &verified_count,
                                 VersioningState *out_versioning_state)
{
  VersioningState vs = VERSIONING_DISABLED;
  if (ctx.has_bucket_future) {
    FdbGetHolder holder(std::move(ctx.f_bkt));
    ctx.has_bucket_future = false;
    auto vb = co_await resolve_bucket_verify_a(params.tenant_id, params.bucket_name,
                                               holder, params.bucket_id, kDenyWrite);
    if (!vb) {
      co_return vb.error();
    }
    vs = vb->versioning_state;
    auto &slot = verified[verified_count++];
    slot.tenant_id = params.tenant_id;
    slot.bucket_name = params.bucket_name;
    slot.state = *vb;
  }
  else {
    bool found = false;
    for (int j = 0; j < verified_count; ++j) {
      if (verified[j].tenant_id == params.tenant_id &&
          verified[j].bucket_name == params.bucket_name) {
        vs = verified[j].state.versioning_state;
        found = true;
        break;
      }
    }
    if (!found) {
      // The bucket read was not issued up front: issue it now and await it.
      auto holder = issue_bucket_get(tr, params.tenant_id, params.bucket_name);
      auto vb = co_await resolve_bucket_verify_a(params.tenant_id, params.bucket_name,
                                                 holder, params.bucket_id, kDenyWrite);
      if (!vb) {
        co_return vb.error();
      }
      vs = vb->versioning_state;
      auto &slot = verified[verified_count++];
      slot.tenant_id = params.tenant_id;
      slot.bucket_name = params.bucket_name;
      slot.state = *vb;
    }
  }
  if (out_versioning_state) {
    *out_versioning_state = vs;
  }

  FdbGetHolder existing(std::move(ctx.f_obj));
  if (const fdb_error_t err = co_await existing) {
    co_return fdb_to_error(err);
  }

  if (ctx.is_storage_tier) {
    if (ctx.f_po) {
      FdbGetHolder po_holder(std::move(ctx.f_po));
      if (const fdb_error_t po_err = co_await po_holder) {
        co_return fdb_to_error(po_err);
      }

      if (!po_holder.present()) {
        if (existing.present()) {
          const auto *h = ovh_ptr(existing.value());
          if (h && h->ref_tag == params.value.hdr.ref_tag) {
            co_return KVRGW_ERR_OK;
          }
        }
        co_return KVRGW_ERR_INTERNAL;
      }

      if (existing.present()) {
        const auto *h = ovh_ptr(existing.value());
        if (h && h->ref_tag == params.value.hdr.ref_tag) {
          tr.kv_del(ctx.po_key.view());
          co_return KVRGW_ERR_OK;
        }
      }
    }
    else {
      if (existing.present()) {
        const auto *h = ovh_ptr(existing.value());
        if (h && h->ref_tag == params.value.hdr.ref_tag) {
          co_return KVRGW_ERR_OK;
        }
      }
    }

    auto ids = install_object_value(tr, vs, ctx.object_key.view(),
                                    existing.value_or_empty(), params.cond, params.value);
    if (!ids) {
      const auto ec = ids.error();
      if ((ec == KVRGW_ERR_PRECONDITION_FAILED || ec == KVRGW_ERR_NO_SUCH_KEY) &&
          ctx.po_key.size() > 0) {
        // Single-request path: the blob and P:O were written in phase 2.
        // Move them to GC in this same transaction (the caller commits it
        // for these two codes). tr holds only reads at this point.
        GcDescriptor gc{};
        gc.chunk = ChunkDescriptor(CHUNK_STORAGE, params.value.hdr.ref_tag,
                                   params.bucket_id);
        gc.object_size = params.value.hdr.size;
        gc.mtime = static_cast<uint32_t>(now_unix());
        PoKeyParts po_parts;
        po_parts.bucket_id = params.bucket_id;
        po_parts.ref_tag = params.value.hdr.ref_tag;
        [[maybe_unused]] const fdb_error_t gc_err =
            move_po_to_go(tr, po_parts, gc, params.object_name);
      }
      co_return ec;
    }

    if (!params.tags.empty()) {
      apply_tags_to_value(params.value, params.tags, tr, params.bucket_id,
                          params.value.hdr.ref_tag.view());
    }

    params.value.set_self_chunk(params.bucket_id);
    size_t written = 0;
    if (!write_o_value(tr, ctx.object_key.view(), params.value, &written)) {
      co_return KVRGW_ERR_VALUE_TOO_LARGE;
    }
    store_.fdb_put_stats().record_value(written);
    write_single_part_children(tr, params);

    if (ctx.po_key.size() > 0) {
      tr.kv_del(ctx.po_key.view());
    }
    co_return KVRGW_ERR_OK;
  }

  // Inline / child-D path
  auto ids = install_object_value(tr, vs, ctx.object_key.view(),
                                  existing.value_or_empty(), params.cond, params.value);
  if (!ids) {
    co_return ids.error();
  }
  if (out_versioning_state) {
    *out_versioning_state = vs;
  }

  if (!params.tags.empty()) {
    apply_tags_to_value(params.value, params.tags, tr, params.bucket_id,
                        params.value.hdr.ref_tag.view());
  }

  params.value.set_self_chunk(params.bucket_id);
  size_t written = 0;
  if (!write_o_value(tr, ctx.object_key.view(), params.value, &written)) {
    co_return KVRGW_ERR_VALUE_TOO_LARGE;
  }
  store_.fdb_put_stats().record_value(written);
  write_single_part_children(tr, params);
  co_return KVRGW_ERR_OK;
}

//--------------------------------------------------------------------------------
async::Task<KvrgwErrorCode>
KvRgwServiceImpl::put_in_txn_a(KvTransaction &tr, PutInTxnParams &params,
                               VersioningState *out_versioning_state)
{
  VerifiedBucket verified[1];
  int vc = 0;
  auto ctx = put_prepare(tr, params, !params.skip_bucket_verify);
  co_return co_await put_finalize_a(tr, ctx, params, verified, vc, out_versioning_state);
}

// ===========================================================================
// Non-batched paths
// ===========================================================================

async::Task<KvrgwErrorCode> KvRgwServiceImpl::put_single_a(
    tenant_id_t tenant_id, std::string_view bucket_name,
    std::string_view object_name, ObjectValue &new_value, std::string_view data,
    VersioningState *out_versioning_state, const PutCondition *cond,
    std::span<const uint8_t> tags, std::span<const uint8_t> metadata)
{
  batch_queue_.stats().single_txn_puts.fetch_add(1, std::memory_order_relaxed);
  const int max_attempts = async_cfg_.txn_max_attempts;

  auto cached_bid = co_await get_bucket_id_cached_a(tenant_id, bucket_name);
  if (!cached_bid) {
    co_return fdb_to_error(cached_bid.error());
  }
  if (!*cached_bid) {
    co_return KVRGW_ERR_NO_SUCH_BUCKET;
  }
  const bucket_id_t bucket_id = (**cached_bid).bucket_id;

  auto tr_result = store_.begin_transaction();
  if (!tr_result) {
    auto ec = fdb_to_error(tr_result.error());
    error_stats_->record(ec);
    co_return ec;
  }
  KvTransaction &tr = **tr_result;
  if (async_cfg_.txn_timeout_ms > 0) (void)tr.set_timeout_ms(async_cfg_.txn_timeout_ms);

  for (int attempt = 1;; ++attempt) {
    PutInTxnParams params{tenant_id, bucket_name, bucket_id, object_name,
                          new_value, data,        cond,
                          tags,      false,       false,     metadata};
    auto ec = co_await put_in_txn_a(tr, params, out_versioning_state);
    if (ec != KVRGW_ERR_OK) {
      error_stats_->record(ec);
      const fdb_error_t read_err = error_to_fdb(ec);
      const bool retry = ec == KVRGW_ERR_INTERNAL || (read_err && is_retriable(ec));
      if (!retry || attempt >= max_attempts) {
        if (retry) {
          latency_stats_.txn_max_retries_exceeded.fetch_add(1, std::memory_order_relaxed);
          co_return KVRGW_ERR_MAX_RETRIES_EXCEEDED;
        }
        co_return ec;
      }
      if (read_err) {
        // A read failed: on_error resets the transaction after FDB's backoff.
        if (fdb_error_t fin = co_await tr.on_error_a(read_err)) {
          co_return fdb_to_error(fin);
        }
      } else {
        tr.reset();
        if (async_cfg_.txn_timeout_ms > 0) (void)tr.set_timeout_ms(async_cfg_.txn_timeout_ms);
      }
      continue;
    }

    const fdb_error_t err = co_await tr.commit_a();
    if (!err) {
      put_bucket_cache(tenant_id, bucket_name, bucket_id, 0,
                       out_versioning_state ? *out_versioning_state : VERSIONING_DISABLED);
      co_return KVRGW_ERR_OK;
    }
    auto commit_ec = fdb_to_error(err);
    error_stats_->record(commit_ec);
    if (!is_retriable(commit_ec)) {
      latency_stats_.txn_hard_failures.fetch_add(1, std::memory_order_relaxed);
      co_return commit_ec;
    }
    if (attempt >= max_attempts) {
      latency_stats_.txn_max_retries_exceeded.fetch_add(1, std::memory_order_relaxed);
      co_return KVRGW_ERR_MAX_RETRIES_EXCEEDED;
    }
    latency_stats_.txn_retries.fetch_add(1, std::memory_order_relaxed);
    if (fdb_error_t fin = co_await tr.on_error_a(err)) {
      co_return fdb_to_error(fin);
    }
  }
}

//--------------------------------------------------------------------------------
async::Task<KvrgwErrorCode> KvRgwServiceImpl::put_phase3_a(
    tenant_id_t tenant_id, std::string_view bucket_name, bucket_id_t bucket_id,
    std::string_view object_name, ObjectValue &new_value,
    VersioningState *out_versioning_state, const PutCondition *cond,
    std::span<const uint8_t> tags, std::span<const uint8_t> metadata)
{
  const int max_attempts = async_cfg_.txn_max_attempts;
  auto tr_result = store_.begin_transaction();
  if (!tr_result) {
    co_return fdb_to_error(tr_result.error());
  }
  KvTransaction &tr = **tr_result;
  if (async_cfg_.txn_timeout_ms > 0) (void)tr.set_timeout_ms(async_cfg_.txn_timeout_ms);

  for (int attempt = 1; attempt <= max_attempts; ++attempt) {
    PutInTxnParams params{tenant_id, bucket_name, bucket_id, object_name,
                          new_value, std::string_view{}, cond,
                          tags,      false,       true,      metadata};
    auto ec = co_await put_in_txn_a(tr, params, out_versioning_state);
    if (ec != KVRGW_ERR_OK) {
      if (ec == KVRGW_ERR_INTERNAL) {
        tr.reset();
        if (async_cfg_.txn_timeout_ms > 0) (void)tr.set_timeout_ms(async_cfg_.txn_timeout_ms);
        continue;
      }
      if (const fdb_error_t read_err = error_to_fdb(ec);
          read_err && is_retriable(ec) && attempt < max_attempts) {
        if (fdb_error_t fin = co_await tr.on_error_a(read_err)) {
          co_return fdb_to_error(fin);
        }
        continue;
      }
      if (ec == KVRGW_ERR_PRECONDITION_FAILED || ec == KVRGW_ERR_NO_SUCH_KEY) {
        // put_finalize queued the blob's move to GC on this transaction.
        // Commit it; whatever the result, report the precondition error (if
        // the commit fails, the sweeper reaches the same outcome later).
        const fdb_error_t cerr = co_await tr.commit_a();
        if (cerr && is_retriable(fdb_to_error(cerr)) && attempt < max_attempts) {
          // A concurrent change to :O: -- re-evaluate the condition.
          if (fdb_error_t fin = co_await tr.on_error_a(cerr)) {
            co_return ec;
          }
          continue;
        }
      }
      co_return ec;
    }

    const fdb_error_t err = co_await tr.commit_a();
    if (!err) {
      put_bucket_cache(tenant_id, bucket_name, bucket_id, 0,
                       out_versioning_state ? *out_versioning_state : VERSIONING_DISABLED);
      co_return KVRGW_ERR_OK;
    }
    auto commit_ec = fdb_to_error(err);
    if (!is_retriable(commit_ec)) {
      co_return commit_ec;
    }
    if (attempt >= max_attempts) break;
    if (fdb_error_t fin = co_await tr.on_error_a(err)) {
      co_return fdb_to_error(fin);
    }
  }
  co_return KVRGW_ERR_MAX_RETRIES_EXCEEDED;
}

//--------------------------------------------------------------------------------
async::Task<KvrgwErrorCode> KvRgwServiceImpl::put_storage_a(
    tenant_id_t tenant_id, std::string_view bucket_name,
    std::string_view object_name, ObjectValue &object_value,
    std::string_view data, uint64_t estimated_size,
    VersioningState *out_versioning_state, const PutCondition *cond,
    std::span<const uint8_t> tags, std::span<const uint8_t> metadata)
{
  auto cached_bid = co_await get_bucket_id_cached_a(tenant_id, bucket_name);
  if (!cached_bid) {
    co_return fdb_to_error(cached_bid.error());
  }
  if (!*cached_bid) {
    co_return KVRGW_ERR_NO_SUCH_BUCKET;
  }

  const bucket_id_t bid = (**cached_bid).bucket_id;
  {
    KeyBuf po_key;
    const auto &ref_tag = object_value.hdr.ref_tag;
    make_po_key(bid, ref_tag.view(), po_key);
    GcDescriptor po_gc{};
    po_gc.chunk = ChunkDescriptor(CHUNK_STORAGE, ref_tag, bid);
    po_gc.object_size = estimated_size;
    po_gc.mtime = static_cast<uint32_t>(now_unix());
    PoValueBuf po_val_buf;
    make_po_value(po_val_buf, po_gc, object_name);
    auto tr = store_.begin_transaction();
    if (!tr) {
      co_return fdb_to_error(tr.error());
    }
    (*tr)->kv_put(po_key.view(), po_val_buf.view());
    if (const fdb_error_t err = co_await (*tr)->commit_a()) {
      co_return fdb_to_error(err);
    }
  }

  // Phase 2: the blob write stays a blocking call on this worker (a no-op for
  // PerfDataStore). Async file I/O is out of scope.
  auto write_ec = data_store_.write(object_value.hdr.ref_tag.filename(), data);
  if (write_ec) {
    co_return KVRGW_ERR_INTERNAL;
  }

  // Fault injection: abort after Phase 2, leaving stale individual P:O + orphan blob
  if (err_insertion_.is_error_active(FaultType::kAbortAfterSinglePhase2)) {
    co_return KVRGW_ERR_INTERNAL;
  }

  co_return co_await put_phase3_a(tenant_id, bucket_name, bid, object_name,
                                  object_value, out_versioning_state, cond, tags,
                                  metadata);
}

// ===========================================================================
// put_object_a / put_object
// ===========================================================================

async::Task<KvRgwServiceImpl::PutObjectResult>
KvRgwServiceImpl::put_object_a(tenant_id_t tenant_id,
                               std::string_view bucket_name,
                               std::string_view object_name,
                               const uint8_t *data, size_t data_len,
                               std::string_view content_type,
                               uint64_t estimated_size,
                               const AWSPutCondition *aws_cond,
                               std::span<const TagPair> tags,
                               std::span<const MetaPair> metadata,
                               Caller caller)
{
  // 1. Admission, on the caller.
  Admission::Guard admitted;
  if (auto ec = admission_.admit(caller, &admitted); ec != KVRGW_ERR_OK) {
    co_return PutObjectResult{ec};
  }
  AsyncRequestLatency lat(latency_stats_, OpType::kPutObject);
  ops_stats_.inc(OpType::kPutObject);

  // 2. Preparation, on the caller: CPU only, no I/O.
  //
  // Two independent, unrelated stats sharing one call site: the exact
  // end-client-supplied object-name and bucket-name lengths, 1:1 with logical
  // PUTs (immune to transaction retries).
  store_.fdb_put_stats().record_key(object_name.size());
  store_.fdb_put_stats().record_bucket_name(bucket_name.size());

  if (content_type.empty()) {
    content_type = "application/octet-stream";
  }

  unsigned char digest[16];
  unsigned int digest_len = 0;
  {
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    if (md5_ctx == nullptr) {
      co_return PutObjectResult{KVRGW_ERR_INTERNAL};
    }
    EVP_DigestInit_ex(md5_ctx, EVP_md5(), nullptr);
    if (data_len > 0) {
      EVP_DigestUpdate(md5_ctx, data, data_len);
    }
    EVP_DigestFinal_ex(md5_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md5_ctx);
  }

  // The batch entry lives in this frame, which stays suspended until the PUT
  // completes; everything it views (this frame's buffers, the caller's data)
  // stays valid.
  BatchCommitEntry entry;
  ObjectValue &object_value = entry.value;
  object_value.hdr.ref_tag = ref_tags_.next();
  object_value.set_etag_raw(digest);
  object_value.hdr.size = data_len;
  stamp_mtime(object_value.hdr);
  object_value.content_type = content_type;

  // Tag and metadata frames are allocated only when present, which keeps this
  // frame within the 2,048-byte pool class for the common case.
  std::unique_ptr<uint8_t[]> tag_buf;
  size_t tag_len = 0;
  if (!tags.empty()) {
    tag_buf = std::make_unique<uint8_t[]>(kMaxTagFrameBytes);
    if (!encode_tags(tags, std::span<uint8_t>(tag_buf.get(), kMaxTagFrameBytes), tag_len)) {
      co_return PutObjectResult{KVRGW_ERR_INVALID_TAG};
    }
  }
  std::unique_ptr<uint8_t[]> meta_buf;
  size_t meta_len = 0;
  if (!metadata.empty()) {
    meta_buf = std::make_unique<uint8_t[]>(MAX_META_FRAME_BYTES);
    if (!encode_metadata(metadata, std::span<uint8_t>(meta_buf.get(), MAX_META_FRAME_BYTES),
                         meta_len)) {
      co_return PutObjectResult{KVRGW_ERR_INVALID_ARGUMENT};
    }
    object_value.hdr.metadata_count = static_cast<uint16_t>(metadata.size());
  }

  const PutCondition *cond_ptr = nullptr;
  if (aws_cond) {
    auto ec = entry.cond.encode(aws_cond->if_match, aws_cond->if_none_match);
    if (ec != KVRGW_ERR_OK) {
      co_return PutObjectResult{ec};
    }
    entry.has_cond = true;
    cond_ptr = &entry.cond;
  }
  const std::span<const uint8_t> tag_span =
      tag_len > 0 ? std::span<const uint8_t>(tag_buf.get(), tag_len) : std::span<const uint8_t>{};
  const std::span<const uint8_t> meta_span =
      meta_len > 0 ? std::span<const uint8_t>(meta_buf.get(), meta_len) : std::span<const uint8_t>{};
  if (estimated_size == 0) estimated_size = data_len;

  // Tier placement, decided once from one tier-config snapshot: inline in :O:,
  // in C:E next to spilled metadata, in C:D, or in the storage tier.
  const auto tc = tier_config_state_.active_copy();
  const std::string_view payload(reinterpret_cast<const char *>(data), data_len);
  SinglePlacementOut placed;
  if (!place_single_part(object_value, meta_span, std::span<const uint8_t>(data, data_len),
                         data_len, tc.max_inline, tc.max_kv_store, placed)) {
    co_return PutObjectResult{KVRGW_ERR_VALUE_TOO_LARGE};
  }
  // Inline data already lives in object_value.inline_data; every other tier
  // takes the body straight from the caller's buffer.
  const std::string_view body = placed.data == DataPlace::kInline ? std::string_view{} : payload;
  const bool is_storage = placed.data == DataPlace::kStorage;

  PutObjectResult result;
  if (tc.batch_size > 1) {
    entry.tenant_id = tenant_id;
    entry.bucket_name = bucket_name;
    entry.object_name = object_name;
    entry.data = body;
    entry.chunk_type = object_value.hdr.chunk_type;
    entry.tag_encoded = tag_span;
    entry.metadata_encoded = meta_span;
    entry.enqueued_at = std::chrono::steady_clock::now();
    // 3. The batcher runs the batch on a backend worker; 4. we are resumed on
    // our own executor.
    const BatchPutResult batch_result = co_await batch_queue_.submit(entry);
    result.error_code = batch_result.error_code;
    if (result.error_code == KVRGW_ERR_OK) {
      result.etag = object_value.etag_display();
      if (batch_result.version_id.is_valid() && !batch_result.version_id.is_null()) {
        result.version_id = batch_result.version_id;
      }
    }
    co_return result;
  }

  // 3. From here to completion the op runs on one backend worker.
  co_await async::switch_to(workers_.next());
  VersioningState vs = VERSIONING_DISABLED;
  if (is_storage) {
    result.error_code = co_await put_storage_a(tenant_id, bucket_name, object_name,
                                               object_value, payload, estimated_size, &vs,
                                               cond_ptr, tag_span, meta_span);
  }
  else {
    result.error_code = co_await put_single_a(tenant_id, bucket_name, object_name,
                                              object_value, body, &vs, cond_ptr, tag_span,
                                              meta_span);
  }
  if (result.error_code == KVRGW_ERR_OK) {
    result.etag = object_value.etag_display();
    if (vs == VERSIONING_ENABLED) {
      result.version_id = object_value.hdr.version_id;
    }
  }
  // 4. Task<> posts the completion back to the caller's executor.
  co_return result;
}

//--------------------------------------------------------------------------------
KvRgwServiceImpl::PutObjectResult
KvRgwServiceImpl::put_object(tenant_id_t tenant_id, std::string_view bucket_name,
                             std::string_view object_name, const uint8_t *data,
                             size_t data_len, std::string_view content_type,
                             uint64_t estimated_size, const AWSPutCondition *cond,
                             std::span<const TagPair> tags,
                             std::span<const MetaPair> metadata)
{
  if (!async::can_sync_wait()) {
    return PutObjectResult{KVRGW_ERR_INTERNAL};
  }
  return async::sync_wait(put_object_a(tenant_id, bucket_name, object_name, data, data_len,
                                       content_type, estimated_size, cond, tags, metadata,
                                       Caller::kSync));
}

// ===========================================================================
// BatchCommitQueue
// ===========================================================================

struct BatchCommitQueue::TaskCount {
  BatchCommitQueue *q;
  explicit TaskCount(BatchCommitQueue *qq) : q(qq) {}
  ~TaskCount() { q->tasks_.fetch_sub(1, std::memory_order_acq_rel); }
};

BatchCommitQueue::BatchCommitQueue(KvRgwServiceImpl &service) : service_(service) {}

BatchCommitQueue::~BatchCommitQueue() { stop(); }

void BatchCommitQueue::start(int)
{
  std::lock_guard lock(mu_);
  stopped_ = false;
}

void BatchCommitQueue::stop()
{
  std::deque<BatchCommitEntry *> drained;
  {
    std::lock_guard lock(mu_);
    stopped_ = true;
    drained.swap(pending_);
  }
  for (auto *e : drained) {
    complete(e, BatchPutResult{KVRGW_ERR_INTERNAL});
  }
}

int BatchCommitQueue::batch_size() const
{
  const int bs = service_.tier_config_state_.active_copy().batch_size;
  return std::clamp(bs, 1, kMaxBatchSize);
}

std::chrono::microseconds BatchCommitQueue::batch_timeout() const
{
  return std::chrono::microseconds(
      std::max(0, service_.tier_config_state_.active_copy().batch_timeout_us));
}

void BatchCommitQueue::complete(BatchCommitEntry *e, BatchPutResult r) noexcept
{
  e->result = r;
  async::Executor *ex = e->waiter_exec ? e->waiter_exec : async::Executor::current();
  std::coroutine_handle<> h = e->waiter;
  if (ex) {
    e->node.h = h;
    ex->post(&e->node);  // last touch of e
  } else {
    h.resume();  // no executor anywhere (shutdown of a sync caller's entry)
  }
}

void BatchCommitQueue::complete_all(std::span<BatchCommitEntry *> es,
                                    KvrgwErrorCode ec) noexcept
{
  for (auto *e : es) {
    complete(e, BatchPutResult{ec});
  }
}

bool BatchCommitQueue::push(BatchCommitEntry *e) noexcept
{
  const int bs = batch_size();
  bool post_form = false;
  bool arm_timer = false;
  std::chrono::steady_clock::time_point deadline;
  {
    std::unique_lock lock(mu_);
    if (stopped_) {
      e->result = BatchPutResult{KVRGW_ERR_INTERNAL};
      return false;
    }
    pending_.push_back(e);
    // One form task per full batch not yet claimed by a posted form task.
    if (pending_.size() >= static_cast<size_t>(bs) * static_cast<size_t>(forming_ + 1)) {
      ++forming_;
      post_form = true;
    }
    if (!timer_armed_) {
      timer_armed_ = true;
      arm_timer = true;
      deadline = pending_.front()->enqueued_at + batch_timeout();
    }
  }
  auto &workers = service_.workers_;
  if (post_form) {
    tasks_.fetch_add(1, std::memory_order_acq_rel);
    const uint32_t i = rr_.fetch_add(1, std::memory_order_relaxed);
    async::spawn(workers.at(static_cast<int>(i % static_cast<uint32_t>(workers.size()))),
                 form_batch());
  }
  if (arm_timer) {
    tasks_.fetch_add(1, std::memory_order_acq_rel);
    async::spawn(workers.at(0), timeout_loop(deadline));
  }
  return true;
}

int BatchCommitQueue::extract_locked(EntryList &out, int bs)
{
  stats_.total_queue_size_at_extract.fetch_add(static_cast<int64_t>(pending_.size()),
                                               std::memory_order_relaxed);
  int n = 0;
  size_t scan = pending_.size();
  while (n < bs && scan-- > 0) {
    BatchCommitEntry *e = pending_.front();
    pending_.pop_front();
    bool dup = false;
    for (int i = 0; i < n; ++i) {
      if (out[static_cast<size_t>(i)]->bucket_name == e->bucket_name &&
          out[static_cast<size_t>(i)]->object_name == e->object_name) {
        dup = true;
        break;
      }
    }
    if (dup) {
      // Same key twice in one transaction would conflict with itself: the
      // later PUT waits for a later batch.
      stats_.conflict_pushbacks.fetch_add(1, std::memory_order_relaxed);
      pending_.push_back(e);
      continue;
    }
    out[static_cast<size_t>(n++)] = e;
  }
  return n;
}

async::Task<void> BatchCommitQueue::form_batch()
{
  TaskCount tc(this);
  EntryList es{};
  int n = 0;
  {
    std::lock_guard lock(mu_);
    --forming_;
    const int bs = batch_size();
    if (!stopped_ && pending_.size() >= static_cast<size_t>(bs)) {
      n = extract_locked(es, bs);
    }
  }
  if (n > 0) {
    tasks_.fetch_add(1, std::memory_order_acq_rel);
    co_await run_batch_task(es, n);
  }
}

async::Task<void> BatchCommitQueue::timeout_loop(std::chrono::steady_clock::time_point deadline)
{
  TaskCount tc(this);
  auto &w0 = service_.workers_.at(0);
  for (;;) {
    co_await w0.sleep_until(deadline);
    EntryList es{};
    int n = 0;
    bool more = false;
    {
      std::lock_guard lock(mu_);
      if (stopped_ || pending_.empty()) {
        timer_armed_ = false;
        co_return;
      }
      const auto timeout = batch_timeout();
      const auto oldest = pending_.front()->enqueued_at;
      if (std::chrono::steady_clock::now() - oldest >= timeout) {
        n = extract_locked(es, batch_size());
      }
      more = !pending_.empty();
      if (more) {
        deadline = pending_.front()->enqueued_at + timeout;
      } else {
        timer_armed_ = false;
      }
    }
    if (n > 0) {
      // Run the partial batch round-robin, like a full one.
      auto &workers = service_.workers_;
      const uint32_t i = rr_.fetch_add(1, std::memory_order_relaxed);
      tasks_.fetch_add(1, std::memory_order_acq_rel);
      async::spawn(workers.at(static_cast<int>(i % static_cast<uint32_t>(workers.size()))),
                   run_batch_task(es, n));
    }
    if (!more) co_return;
  }
}

async::Task<void> BatchCommitQueue::run_batch_task(EntryList es, int n)
{
  TaskCount tc(this);
  co_await run_batch(std::span<BatchCommitEntry *>(es.data(), static_cast<size_t>(n)));
}

void BatchCommitQueue::record_batch_stats(std::span<BatchCommitEntry *> es)
{
  auto now = std::chrono::steady_clock::now();
  int64_t bs = static_cast<int64_t>(es.size());
  stats_.attempted_batch_commits.fetch_add(1, std::memory_order_relaxed);
  stats_.attempted_total_entries_batch.fetch_add(bs, std::memory_order_relaxed);
  if (bs == 1) {
    stats_.attempted_single_entry_batches.fetch_add(1, std::memory_order_relaxed);
  }
  atomic_min(stats_.attempted_min_batch_size, bs);
  atomic_max(stats_.attempted_max_batch_size, bs);
  auto oldest = es[0]->enqueued_at;
  for (auto *e : es) {
    oldest = std::min(oldest, e->enqueued_at);
  }
  int64_t wait_us = duration_cast<microseconds>(now - oldest).count();
  stats_.attempted_total_wait_us.fetch_add(wait_us, std::memory_order_relaxed);
  atomic_min(stats_.attempted_min_wait_us, wait_us);
  atomic_max(stats_.attempted_max_wait_us, wait_us);
}

async::Task<KvrgwErrorCode>
BatchCommitQueue::resolve_bucket_ids(std::span<BatchCommitEntry *> es)
{
  for (auto *e : es) {
    // A cache hit does not suspend.
    auto cached = co_await service_.get_bucket_id_cached_a(e->tenant_id, e->bucket_name);
    if (!cached) {
      co_return fdb_to_error(cached.error());
    }
    if (!*cached) {
      co_return KVRGW_ERR_NO_SUCH_BUCKET;
    }
    e->bucket_id = (**cached).bucket_id;
  }
  co_return KVRGW_ERR_OK;
}

async::Task<void> BatchCommitQueue::fallback_to_single(std::span<BatchCommitEntry *> es)
{
  stats_.fallback_to_single_count.fetch_add(1, std::memory_order_relaxed);
  stats_.fallback_to_single_entries.fetch_add(static_cast<int64_t>(es.size()),
                                              std::memory_order_relaxed);
  // In order, one at a time, as before. (Running them concurrently is a later
  // optimisation.)
  for (auto *e : es) {
    const PutCondition *cond_ptr = e->has_cond ? &e->cond : nullptr;
    auto ec = co_await service_.put_single_a(e->tenant_id, e->bucket_name, e->object_name,
                                             e->value, e->data, nullptr, cond_ptr,
                                             e->tag_encoded, e->metadata_encoded);
    complete(e, BatchPutResult{ec, e->value.hdr.version_id});
  }
}

async::Task<void> BatchCommitQueue::run_batch(std::span<BatchCommitEntry *> es)
{
  auto &svc = service_;
  const auto &acfg = svc.async_cfg_;
  constexpr int kMaxStartRetries = 3;
  constexpr int kMaxPrepAttempts = 3;

  // ---------------------------------------------------------------
  // Step 1: bucket ids. Retriable errors retry up to 3 times; anything else
  // (or running out) falls back to one transaction per entry.
  // ---------------------------------------------------------------
  for (int retries = 0;; ++retries) {
    const auto ec = co_await resolve_bucket_ids(es);
    if (ec == KVRGW_ERR_OK) break;
    svc.error_stats_->record(ec);
    if (!is_retriable(ec) || retries >= kMaxStartRetries) {
      co_await fallback_to_single(es);
      co_return;
    }
  }

  bool has_storage = false;
  for (auto *e : es) {
    has_storage |= e->chunk_type == CHUNK_STORAGE;
  }

  // Big per-batch scratch (P:O keys, per-entry contexts) lives on the heap so
  // this frame stays small.
  struct Scratch {
    KeyBuf p1_keys[kMaxPhase1Keys];
    KvRgwServiceImpl::PutContext ctxs[kMaxBatchSize];
    KvRgwServiceImpl::VerifiedBucket verified[kMaxBatchSize];
  };
  auto sc = std::make_unique<Scratch>();
  int n_p1 = 0;

  if (!has_storage) {
    stats_.attempted_inline_only_batch_commits.fetch_add(1, std::memory_order_relaxed);
    stats_.attempted_inline_only_batch_entries.fetch_add(static_cast<int64_t>(es.size()),
                                                         std::memory_order_relaxed);
  } else {
    // ---------------------------------------------------------------
    // Phase 1: Group P:O / single P:O keys for the storage-tier entries,
    // flushing when the accumulator is full or the variable section would
    // overflow 2 x AWS_MaxObjectNameLen.
    // ---------------------------------------------------------------
    static constexpr size_t kMaxNameBytes = 2 * AWS_MaxObjectNameLen;
    auto tr_result = svc.store_.begin_transaction();
    if (!tr_result) {
      const auto ec = fdb_to_error(tr_result.error());
      svc.error_stats_->record(ec);
      co_await fallback_to_single(es);
      co_return;
    }
    KvTransaction &p1 = **tr_result;

    GroupPoValue accumulator{};
    uint16_t name_bytes{0};
    auto flush_as_group_po = [&]() {
      const auto ref_view = accumulator.entries[0].gc.chunk.ref_tag_view();
      const auto bid = accumulator.entries[0].gc.chunk.get_bucket_id();
      KeyBuf &key = sc->p1_keys[n_p1];
      make_group_po_key(bid, ref_view, key);
      GroupPoValueBuf val_buf;
      make_group_po_value(val_buf, accumulator);
      p1.kv_put(key.view(), val_buf.view());
      ++n_p1;
      accumulator = GroupPoValue{};
      name_bytes = 0;
    };
    auto flush_as_single_po = [&]() {
      const auto &gc = accumulator.entries[0].gc;
      const std::string_view object_name = accumulator.entries[0].object_name;
      KeyBuf &key = sc->p1_keys[n_p1];
      make_po_key(gc.chunk.get_bucket_id(), gc.chunk.ref_tag_view(), key);
      PoValueBuf val_buf;
      make_po_value(val_buf, gc, object_name);
      p1.kv_put(key.view(), val_buf.view());
      ++n_p1;
      accumulator = GroupPoValue{};
      name_bytes = 0;
    };

    for (auto *e : es) {
      if (e->chunk_type != CHUNK_STORAGE) continue;
      if (accumulator.count == 0 && name_bytes == 0) {
        accumulator.created_at_unix = static_cast<uint32_t>(now_unix());
      }
      const size_t this_name_len = e->object_name.size();
      if (accumulator.count == kMaxGroupPoSize ||
          (accumulator.count >= 2 &&
           static_cast<size_t>(name_bytes) + this_name_len > kMaxNameBytes)) {
        flush_as_group_po();
      }
      auto &slot = accumulator.entries[accumulator.count];
      slot.gc.chunk = ChunkDescriptor(CHUNK_STORAGE, e->value.hdr.ref_tag, e->bucket_id);
      slot.gc.object_size = e->value.hdr.size;
      slot.gc.mtime = accumulator.created_at_unix;
      slot.object_name = e->object_name;
      accumulator.count++;
      name_bytes = static_cast<uint16_t>(name_bytes + this_name_len);
    }
    if (accumulator.count >= 2) {
      flush_as_group_po();
    } else if (accumulator.count == 1) {
      flush_as_single_po();
    }

    record_batch_stats(es);

    if (const fdb_error_t err = co_await p1.commit_a()) {
      const auto ec = fdb_to_error(err);
      svc.error_stats_->record(ec);
      complete_all(es, ec);
      co_return;
    }

    // ---------------------------------------------------------------
    // Phase 2: blobs. data_store_.write stays a blocking call on this worker
    // (a no-op for PerfDataStore); async file I/O is out of scope.
    // ---------------------------------------------------------------
    for (auto *e : es) {
      if (e->chunk_type != CHUNK_STORAGE) continue;
      if (svc.data_store_.write(e->value.hdr.ref_tag.filename(), e->data)) {
        svc.error_stats_->record(KVRGW_ERR_INTERNAL);
        complete_all(es, KVRGW_ERR_INTERNAL);
        co_return;
      }
    }
    if (svc.err_insertion_.is_error_active(FaultType::kAbortAfterBatchPhase2)) {
      complete_all(es, KVRGW_ERR_INTERNAL);
      co_return;
    }
  }

  // ---------------------------------------------------------------
  // Phase 3: one transaction writes every :O: value, checks the phase-1 keys
  // are still there and deletes them. Reads are all issued before the first
  // co_await, so the wait is the slowest read, not their sum.
  // ---------------------------------------------------------------
  auto tr_result = svc.store_.begin_transaction();
  if (!tr_result) {
    const auto ec = fdb_to_error(tr_result.error());
    svc.error_stats_->record(ec);
    complete_all(es, ec);
    co_return;
  }
  KvTransaction &tr = **tr_result;
  if (acfg.txn_timeout_ms > 0) (void)tr.set_timeout_ms(acfg.txn_timeout_ms);

  for (int prep_fail = 0, commit_fail = 0;;) {
    // Issue: one get per phase-1 key, then bucket + object reads per entry.
    std::unique_ptr<FdbGetHolder> p1h[kMaxPhase1Keys];
    for (int k = 0; k < n_p1; ++k) {
      p1h[k] = std::make_unique<FdbGetHolder>(tr.kv_async_get(sc->p1_keys[k].view()));
    }
    int verified_count = 0;
    for (size_t i = 0; i < es.size(); ++i) {
      auto *e = es[i];
      bool need_bucket = true;
      for (size_t j = 0; j < i; ++j) {
        if (es[j]->tenant_id == e->tenant_id && es[j]->bucket_name == e->bucket_name) {
          need_bucket = false;
          break;
        }
      }
      // is_storage_tier=false suppresses the per-entry P:O read (phase-1 keys
      // are checked as a whole); restored below so put_finalize takes the
      // storage path.
      KvRgwServiceImpl::PutInTxnParams params{
          e->tenant_id, e->bucket_name, e->bucket_id, e->object_name, e->value,
          e->data, nullptr, e->tag_encoded, !need_bucket, false, e->metadata_encoded};
      sc->ctxs[i] = svc.put_prepare(tr, params, need_bucket);
      sc->ctxs[i].is_storage_tier = e->chunk_type == CHUNK_STORAGE;
    }

    // Resolve: put_finalize per entry, in order; stop at the first failure.
    KvrgwErrorCode ec = KVRGW_ERR_OK;
    for (size_t i = 0; i < es.size() && ec == KVRGW_ERR_OK; ++i) {
      auto *e = es[i];
      const PutCondition *cond_ptr = e->has_cond ? &e->cond : nullptr;
      KvRgwServiceImpl::PutInTxnParams params{
          e->tenant_id, e->bucket_name, e->bucket_id, e->object_name, e->value,
          e->data, cond_ptr, e->tag_encoded, false, e->chunk_type == CHUNK_STORAGE,
          e->metadata_encoded};
      ec = co_await svc.put_finalize_a(tr, sc->ctxs[i], params, sc->verified,
                                       verified_count, nullptr);
    }
    // Phase-1 keys still present?
    for (int k = 0; k < n_p1 && ec == KVRGW_ERR_OK; ++k) {
      if (const fdb_error_t err = co_await *p1h[k]) {
        ec = fdb_to_error(err);
      } else if (!p1h[k]->present()) {
        ec = KVRGW_ERR_INTERNAL;
      }
    }
    if (ec == KVRGW_ERR_OK) {
      for (int k = 0; k < n_p1; ++k) {
        tr.kv_del(sc->p1_keys[k].view());
      }
    }
    // Every issued read has resolved (or is about to be dropped with the
    // reset below): no callback can be pending past this point.
    for (int k = 0; k < n_p1; ++k) p1h[k].reset();

    if (ec != KVRGW_ERR_OK) {
      // Preparing / finalizing failed: up to 3 attempts for retriable errors.
      svc.error_stats_->record(ec);
      const fdb_error_t read_err = error_to_fdb(ec);
      if (!is_retriable(ec) || ++prep_fail >= kMaxPrepAttempts) {
        complete_all(es, ec);
        co_return;
      }
      // A retriable read error goes through on_error, which resets the
      // transaction after FDB's backoff.
      if (read_err == 0) {
        tr.reset();
        if (acfg.txn_timeout_ms > 0) (void)tr.set_timeout_ms(acfg.txn_timeout_ms);
      } else if (const fdb_error_t fin = co_await tr.on_error_a(read_err)) {
        complete_all(es, fdb_to_error(fin));
        co_return;
      }
      continue;
    }

    const fdb_error_t err = co_await tr.commit_a();
    if (!err) {
      const int64_t bs = static_cast<int64_t>(es.size());
      stats_.committed_batch_commits.fetch_add(1, std::memory_order_relaxed);
      stats_.committed_total_entries.fetch_add(bs, std::memory_order_relaxed);
      if (bs == 1) {
        stats_.committed_single_entry_batches.fetch_add(1, std::memory_order_relaxed);
      }
      if (n_p1 == 0) {
        stats_.committed_inline_only_batch_commits.fetch_add(1, std::memory_order_relaxed);
        stats_.committed_inline_only_batch_entries.fetch_add(bs, std::memory_order_relaxed);
      }
      for (auto *e : es) {
        complete(e, BatchPutResult{KVRGW_ERR_OK, e->value.hdr.version_id});
      }
      co_return;
    }
    // Commit failed: up to batch_txn_max_attempts (10) for retriable errors.
    const auto commit_ec = fdb_to_error(err);
    if (!is_retriable(commit_ec)) {
      svc.error_stats_->record(commit_ec);
      svc.latency_stats_.txn_hard_failures.fetch_add(1, std::memory_order_relaxed);
      complete_all(es, commit_ec);
      co_return;
    }
    if (++commit_fail >= acfg.batch_txn_max_attempts) {
      svc.error_stats_->record(commit_ec);
      svc.latency_stats_.txn_max_retries_exceeded.fetch_add(1, std::memory_order_relaxed);
      complete_all(es, commit_ec);
      co_return;
    }
    svc.latency_stats_.txn_retries.fetch_add(1, std::memory_order_relaxed);
    if (const fdb_error_t fin = co_await tr.on_error_a(err)) {
      svc.error_stats_->record(fdb_to_error(fin));
      complete_all(es, fdb_to_error(fin));
      co_return;
    }
  }
}

}  // namespace kvrgw
