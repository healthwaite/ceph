// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <fmt/format.h>
#include <string>

#include "cls/rgw/cls_rgw_types.h"
#include "common/dout.h"
#include "rgw_common.h"
#include "rgw_rest_storequery.h"
#include "rgw_sal_rados.h"
#include "rgw_url.h"

// #define dout_context g_ceph_context
// #define dout_subsys ceph_subsys_rgw

void RGWStoreQueryOp_Ping::execute(optional_yield y)
{
  ldpp_dout(this, 20) << fmt::format("{}: {}({})", typeid(this).name(), __func__, request_id_) << dendl;
  // This can't fail.
  op_ret = 0;
}

void RGWStoreQueryOp_Ping::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section("StoreQueryPingResult");
  s->formatter->dump_string("request_id", request_id_);
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

static const char* SQ_HEADER = "HTTP_X_RGW_STOREQUERY";
static const char* HEADER_LC = "x-rgw-storequery";

void RGWStoreQueryOp_ObjectStatus::execute(optional_yield y)
{
  bucket_name_ = rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name);
  object_key_name_ = s->object->get_key().name;

  ldpp_dout(this, 20) << fmt::format("{}: {} (bucket='{}' object='{}')",
      typeid(this).name(), __func__, bucket_name_, object_key_name_)
                      << dendl;

  bool found = false;

  //
  // Query already-existing objects (the most common case).
  //

  rgw::sal::Bucket::ListParams params{};
  params.prefix = object_key_name_;
  // We want results even if the last object is a delete marker. In a bucket
  // without versioning a query for a deleted or nonexistent object will
  // return zero objects, for which we'll return ENOENT.
  params.list_versions = true;
  // We always want an ordered list of objects. This is the default atow.
  params.allow_unordered = false;

  do {
    rgw::sal::Bucket::ListResults results;
    // This is the 'page size' for the bucket list. We're unlikely to have
    // more than a thousand versions, but we're querying a prefix and there
    // could easily be a *lot* of objects with the given prefix.
    constexpr int version_query_max = 1000;

    ldpp_dout(this, 20) << fmt::format("issue bucket list() query next_marker={}", params.marker.name) << dendl;
    // NOTE: rgw::sal::RadosBucket::list() updates params.marker as it
    // goes.
    auto ret = s->bucket->list(this, params, version_query_max, results, y);

    if (ret < 0) {
      op_ret = ret;
      ldpp_dout(this, 2) << "sal bucket->list query failed ret=" << ret << dendl;
      return;
    }

    if (results.objs.size() == 0) {
      // EOF. Exit the simple search loop.
      ldpp_dout(this, 20) << fmt::format("bucket list() prefix='{}' EOF", object_key_name_) << dendl;
      break;

    } else {
      for (size_t n=0; n<results.objs.size(); n++) {
        auto &obj = results.objs[n];
        // Check for exact key match - we searched a prefix.
        if (obj.key.name != object_key_name_) {
          ldpp_dout(this, 20) << fmt::format("ignore non-exact match key={}", obj.key.name) << dendl;
          continue;
        }

        found = true;
        ldpp_dout(this, 20) <<
          fmt::format("obj {}/{}: exists={} current={} delete_marker={}",
            n, results.objs.size(), obj.exists, obj.is_current(), obj.is_delete_marker())
            << dendl;
        if (obj.is_current()) {
          object_deleted_ = obj.is_delete_marker();
          if (!object_deleted_) {
            object_size_ = obj.meta.size;
          }
          // We've found a matching, current object. We're done.
          break;
        }
      }
    }
  } while (!found);

  if (found) {
    ldpp_dout(this, 20) << fmt::format("found key={} in standard path", object_key_name_) << dendl;
    op_ret = 0;
    return;
  }

  //
  // Query in-progress multipart uploads (less common).
  //

  std::vector<std::unique_ptr<rgw::sal::MultipartUpload>> uploads{};
  std::string marker{""};
  std::string delimiter{""};
  constexpr int mp_query_max = 1000;
	bool is_truncated; // Must be present, pointer to this is unconditionally
                     // written by list_multiparts().

  do {
    // Re-initialise this every run. We can only see if the query is complete
    // across multiple list_multiparts() by checking if this is empty.
    // However, nothing in list_multiparts() clears it.
    uploads.clear();

    ldpp_dout(this, 20) << fmt::format("issue list_multiparts() query marker='{}'", marker) << dendl;
    // Note that 'marker' is an inout param.
    auto ret = s->bucket->list_multiparts(this, object_key_name_, marker, delimiter,
                                            mp_query_max, uploads, nullptr,
                                            &is_truncated);
    if (ret < 0) {
      ldpp_dout(this, 5) << "list_multiparts() failed with code " << ret << dendl;
      break;
    }

    // uploads is only
    if (uploads.size() == 0) {
      ldpp_dout(this, 20) << fmt::format("list_multiparts() prefix='{}' EOF", object_key_name_) << dendl;
      break;
    }

    for (auto const& upload: uploads) {
      if (upload->get_key() == object_key_name_) {
        object_mpuploading_ = true;
        object_mpupload_id_ = upload->get_upload_id();
        ldpp_dout(this, 20) << fmt::format("multipart upload found for object={} upload_id='{}'",
                                upload->get_key(), object_mpupload_id_) << dendl;
        // This exact key is being mpuploaded to this cluster. We're done.
        found = true;
        break;
      }
    }
  } while (!found);

  if (found) {
    ldpp_dout(this, 20) << fmt::format("found key={} in mp upload path", object_key_name_) << dendl;
    op_ret = 0;
    return;
  }

  // Not found anywhere.
  ldpp_dout(this, 2) << "key not found" << dendl;
  op_ret = -ENOENT;
  return;
}

void RGWStoreQueryOp_ObjectStatus::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");

  dump_start(s);
  s->formatter->open_object_section("StoreQueryObjectStatusResult");
  s->formatter->open_object_section("Object");
  s->formatter->dump_string("bucket", bucket_name_);
  s->formatter->dump_string("key", object_key_name_);
  s->formatter->dump_bool("deleted", object_deleted_);
  s->formatter->dump_bool("multipart_upload_in_progress", object_mpuploading_);
  if (object_mpuploading_) {
    s->formatter->dump_string("multipart_upload_id", object_mpupload_id_);
  }
  if (!object_deleted_ && !object_mpuploading_) {
    s->formatter->dump_string("version_id", version_id_);
    s->formatter->dump_int("size", static_cast<int64_t>(object_size_));
  }
  s->formatter->close_section();
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

namespace ba = boost::algorithm;

void RGWSQHeaderParser::reset()
{
  op_ = nullptr;
  command_ = "";
  param_.clear();
}

bool RGWSQHeaderParser::tokenize(const DoutPrefixProvider* dpp, const std::string& input)
{
  if (input.empty()) {
    ldpp_dout(dpp, 0) << fmt::format("illegal empty {} header", HEADER_LC) << dendl;
    return false;
  }
  if (input.size() > RGWSQMaxHeaderLength) {
    ldpp_dout(dpp, 0) << fmt::format("{} header exceeds maximum length of {} chars",
        HEADER_LC, RGWSQMaxHeaderLength)
                      << dendl;
    return false;
  }
  // Enforce ASCII-7 non-control characters.
  if (!std::all_of(input.cbegin(), input.cend(), [](auto c) {
        return c >= ' ';
      })) {
    ldpp_dout(dpp, 0) << fmt::format("Illegal character found in {}", HEADER_LC) << dendl;
    return false;
  }

  // Only debug the header contents after canonicalising it.
  ldpp_dout(dpp, 20) << fmt::format("header {}: '{}'", HEADER_LC, input) << dendl;

  // Use boost::tokenizer to split into space-separated fields, allowing
  // double-quoted fields to contain spaces.
  boost::escaped_list_separator<char> els("\\", " ", "\"");
  boost::tokenizer<boost::escaped_list_separator<char>> tok { input, els };
  bool first = true;
  for (const auto& t : tok) {
    if (first) {
      // Always lowercase the command name.
      command_ = ba::to_lower_copy(t);
      first = false;
      continue;
    }
    param_.push_back(std::string { t });
  }
  return true;
}

bool RGWSQHeaderParser::parse(const DoutPrefixProvider* dpp, const std::string& input, RGWSQHandlerType handler_type)
{
  op_ = nullptr;
  if (!tokenize(dpp, input)) {
    return false;
  }
  if (command_.empty()) {
    ldpp_dout(dpp, 0) << fmt::format("{}: no command found", HEADER_LC) << dendl;
    return false;
  }
  // ObjectStatus command.
  //
  if (command_ == "objectstatus") {
    if (handler_type != RGWSQHandlerType::Obj) {
      ldpp_dout(dpp, 0) << fmt::format("{}: ObjectStatus only applies in an Object context", HEADER_LC) << dendl;
      return false;
    }
    if (param_.size() != 0) {
      ldpp_dout(dpp, 0) << fmt::format("{}: malformed ObjectStatus command (expected zero args)", HEADER_LC) << dendl;
      return false;
    }
    op_ = new RGWStoreQueryOp_ObjectStatus();
    return true;
  }
  // Ping command.
  //
  else if (command_ == "ping") {
    // Allow ping from any handler type - it doesn't matter!
    if (param_.size() != 1) {
      ldpp_dout(dpp, 0) << fmt::format("{}: malformed Ping command (expected one arg)", HEADER_LC) << dendl;
      return false;
    }
    op_ = new RGWStoreQueryOp_Ping(param_[0]);
    return true;
  }
  return false;
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_get()
{
  auto hdr = s->info.env->get(SQ_HEADER, nullptr);
  if (!hdr) {
    // Nothing to do if the x-rgw-storequery header is absent.
    return nullptr;
  }
  DoutPrefix dpp { g_ceph_context, ceph_subsys_rgw, "storequery_parse " };

  // Our x- header is present - if we fail to parse now, we need to signal an
  // error up the stack and not continue processing.
  auto p = RGWSQHeaderParser();
  if (!p.parse(&dpp, hdr, handler_type_)) {
    ldpp_dout(&dpp, 0) << fmt::format("{}: parser failure", HEADER_LC) << dendl;
    throw -ERR_INTERNAL_ERROR;
  }
  return p.op();
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_put()
{
  // We don't handle PUT requests yet.
  return nullptr;
}
RGWOp* RGWHandler_REST_StoreQuery_S3::op_delete()
{
  // We don't handle DELETE requests yet.
  return nullptr;
}
