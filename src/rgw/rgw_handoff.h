// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef RGW_HANDOFF_H
#define RGW_HANDOFF_H

#include "acconfig.h"

#include <fmt/format.h>
#include <string>

#include "common/async/yield_context.h"
#include "common/ceph_context.h"
#include "common/dout.h"
#include "rgw/rgw_common.h"

namespace rgw {

class HandoffAuthResult {
	std::string userid_ = "";
	int errorcode_ = 0;
	bool is_err_ = false;

public:
	HandoffAuthResult(const std::string& userid) : userid_{userid}, is_err_{false} {};
	HandoffAuthResult(int errorcode) : errorcode_{errorcode}, is_err_{true} {};

	bool is_err() { return is_err_; }
	bool is_ok() { return !is_err_; }
	int code() { return errorcode_; }
	std::string userid() { return userid_; }

	std::string to_string() {
		if (is_err()) {
			return fmt::format("error={}", errorcode_);
		} else {
			return fmt::format("userid='{}'", userid_);
		}
	}
};

/**
 * @brief Support class for 'handoff' authentication.
 */
class HandoffHelper {
    std::string uri_;

public:

    HandoffHelper(std::string _uri) : uri_(std::move(_uri)) {
	// XXX
     }
    ~HandoffHelper() {
	// XXX
     }

    int init(CephContext *const cct);
    HandoffAuthResult auth(const DoutPrefixProvider *dpp,
	const std::string& session_token,
	const std::string& access_key_id,
	const std::string& string_to_sign,
	const std::string& signature,
	const req_state* const s,
  	optional_yield y);
};

} /* namespace rgw */

#endif /* RGW_HANDOFF_H */
