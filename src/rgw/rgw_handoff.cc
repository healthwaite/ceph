// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_handoff.h"

#include <boost/algorithm/string.hpp>
#include <string>
#include <fmt/format.h>

#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_http_client_curl.h"

#define dout_subsys ceph_subsys_rgw

namespace ba = boost::algorithm;

namespace rgw {

  int HandoffHelper::init(CephContext *const cct) {
    ldout(cct, 20) << "HandoffHelper::init" << dendl;
    return 0; // XXX
  };

  HandoffAuthResult HandoffHelper::auth(const DoutPrefixProvider *dpp,
	const std::string& session_token,
	const std::string& access_key_id,
	const std::string& string_to_sign,
	const std::string& signature,
	const req_state* const s,
	optional_yield y) {

	ldpp_dout(dpp, 10) << "HandoffHelper::auth()" << dendl;

	auto cct = dpp->get_cct();
	auto url = cct->_conf->rgw_handoff_uri;
	if (!ba::ends_with(url, "/")) {
		url += "/";
	}
	// This is the query path.
	url += "verify";

	std::string body{"foo"};

	ceph::bufferlist bl;
	RGWHTTPTransceiver verify{cct, "POST", url, &bl};
	ldpp_dout(dpp, 20) << fmt::format("fetch '{}'", url) << dendl;

	verify.set_post_data(body);
	verify.set_send_length(body.length());

	auto ret = RGWHTTP::process(&verify, y);

	if (ret < 0) {
		ldpp_dout(dpp, 20) << fmt::format("fetch '{}' exit code {}", url, ret) << dendl;
		return HandoffAuthResult(-EACCES);
	}

	auto status = verify.get_http_status();
	ldpp_dout(dpp, 20) << fmt::format("fetch '{}' status {}", url, status) << dendl;

	// These error code responses mimic rgw_auth_keystone.cc.
	switch (status) {
	case 200:
		// Happy path.
		break;
	case 401:
		return HandoffAuthResult(-ERR_SIGNATURE_NO_MATCH);
	case 404:
		return HandoffAuthResult(-ERR_INVALID_ACCESS_KEY);
	case RGWHTTPClient::HTTP_STATUS_NOSTATUS:
		ldpp_dout(dpp, 5) << fmt::format("fetch '{}' unknown status {}", url, status) << dendl;
		return HandoffAuthResult(-EACCES);
	}

	return HandoffAuthResult("testid"); // XXX!!!
	// return HandoffAuthResult(-EACCES);
  };

} /* namespace rgw */
