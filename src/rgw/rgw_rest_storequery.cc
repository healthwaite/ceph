// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>
#include <fmt/format.h>
#include <string>

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

  // Read cribbed from RGWGetObj::execute() and vastly simplified.

  std::unique_ptr<rgw::sal::Object::ReadOp> read_op(s->object->get_read_op(s->obj_ctx));

  op_ret = read_op->prepare(s->yield, this);
  if (op_ret < 0) {
    // Try to give a helpful log message, we really expect ENOENT as we're not
    // setting read attributes.
    if (op_ret == -ENOENT) {
      ldpp_dout(this, 20) << "read_op return ENOENT, object not found" << dendl;
    } else {
      ldpp_dout(this, 20) << "read_op failed err=" << op_ret << dendl;
    }
    return;
  }
  // Gather other information that may be useful.
  version_id_ = s->object->get_instance();
  object_size_ = s->obj_size = s->object->get_obj_size();

  op_ret = 0;
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
  s->formatter->dump_bool("present", true);
  s->formatter->dump_string("version_id", version_id_);
  s->formatter->dump_int("size", static_cast<int64_t>(object_size_));
  s->formatter->close_section();
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

namespace ba = boost::algorithm;

void RGWSQHeaderParser::reset()
{
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
  ldpp_dout(&dpp, 20) << fmt::format("header {}: '{}'", HEADER_LC, hdr) << dendl;

  // Our x- header is present - if we fail to parse now, we need to signal an
  // error up the stack and not continue processing.
  auto p = RGWSQHeaderParser();
  if (!p.parse(&dpp, hdr, handler_type_)) {
    ldpp_dout(&dpp, 20) << fmt::format("{}: parser failure", HEADER_LC) << dendl;
    throw -ERR_INTERNAL_ERROR;
  }
  return p.op();
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_put() {
  // We don't handle PUT requests yet.
  return nullptr;
}
RGWOp* RGWHandler_REST_StoreQuery_S3::op_delete() {
  // We don't handle DELETE requests yet.
  return nullptr;
}
