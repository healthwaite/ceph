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

namespace ba = boost::algorithm;

void RGWStoreQueryPing::execute(optional_yield y)
{
  ldpp_dout(this, 20) << fmt::format("{}: {}({})", typeid(this).name(), __func__, request_id_) << dendl;
  // This can't fail.
  op_ret = 0;
}

void RGWStoreQueryPing::send_response()
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
      command_ = std::string { t };
      first = false;
      continue;
    }
    param_.push_back(std::string { t });
  }
  return true;
}

bool RGWSQHeaderParser::parse(const DoutPrefixProvider* dpp, const std::string& input)
{
  if (!tokenize(dpp, input)) {
    return false;
  }
  if (command_.empty()) {
    ldpp_dout(dpp, 0) << fmt::format("{}: no command found", HEADER_LC) << dendl;
    return false;
  }
  auto cmd = ba::to_lower_copy(command_);
  if (cmd == "ping") {
    if (param_.size() != 1) {
      ldpp_dout(dpp, 0) << fmt::format("{}: malformed ping command (expected one arg)", HEADER_LC) << dendl;
      return false;
    }
    op_ = new RGWStoreQueryPing(param_[0]);
    return true;
  }
  return false;
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_get()
{
  DoutPrefix dpp { g_ceph_context, ceph_subsys_rgw, "storequery_parse " };
  auto hdr = s->info.env->get(SQ_HEADER, nullptr);
  if (!hdr) {
    // Nothing to do if the x-rgw-storequery header is absent.
    return nullptr;
  }
  ldpp_dout(&dpp, 20) << fmt::format("header {}: '{}'", HEADER_LC, hdr) << dendl;

  // Our x- header is present - if we fail to parse now, we need to signal an
  // error up the stack and not continue processing.
  auto p = RGWSQHeaderParser();
  if (!p.parse(&dpp, hdr)) {
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
