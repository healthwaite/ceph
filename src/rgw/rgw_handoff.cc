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


	// The 'environment' of the request includes, amongst other things,
	// all the headers, prefixed with 'HTTP_'. They also have header names
	// uppercased and with underscores instead of hyphens.
	auto envmap = s->cio->get_env().get_map();

	// Fetch the URI for the authentication REST endpoint.
	auto cct = dpp->get_cct();
	auto query_url = cct->_conf->rgw_handoff_uri;
	if (!ba::ends_with(query_url, "/")) {
		query_url += "/";
	}
	// This is the query path.
	query_url += "verify";

	// If the client uses TLS, key SERVER_PORT_SECURE is found in the env.
	auto srch = envmap.find("SERVER_PORT_SECURE");
	auto proto = (srch == envmap.end()) ? "http" : "https";

	auto gen_url = fmt::format("{}://{}{}", proto, s->info.host, s->info.request_uri);

	/* Send a document like this:

	 {
	   "method": "GET",
	   "url": "http://1.2.3.4:8000/test",
	   "headers": {
		"host": "1.2.3.4:8000",
		... etc ...
	   }
	 }
	 */

	JSONFormatter jf{true};
	jf.open_object_section(""); // root
	encode_json("method", s->info.method, &jf);
	encode_json("url", gen_url, &jf);
	jf.open_object_section("headers"); // "headers"

	// Dump the HTTP header subsection of the env, transforming the keys
	// back into a well-known form.
	//
	// XXX we should probably filter this further, there's no reason to
	// XXcopy more keys than we need.
	for (const auto& kv: envmap) {
		auto key = kv.first;
		// Original headers are prefixed 'HTTP_'.
		if (boost::algorithm::starts_with(key, "HTTP_")) {
			// Change to lower case, and replace underscores with
			// hyphens.
			ba::erase_first(key, "HTTP_");
			ba::to_lower(key);
			ba::replace_all(key, "_", "-");
			// Include in the JSON output.
			encode_json(key.c_str(), kv.second.c_str(), &jf);
		}
	}

	jf.close_section(); // "headers"
	jf.close_section(); // root

	std::ostringstream oss;
	jf.flush(oss);

	ceph::bufferlist bl;
	RGWHTTPTransceiver verify{cct, "POST", query_url, &bl};
	ldpp_dout(dpp, 20) << fmt::format("fetch '{}': post '{}'", query_url, oss.str()) << dendl;

	verify.set_post_data(oss.str());
	verify.set_send_length(oss.str().length());

	auto ret = RGWHTTP::process(&verify, y);

	if (ret < 0) {
		ldpp_dout(dpp, 5) << fmt::format("fetch '{}' exit code {}", query_url, ret) << dendl;
		return HandoffAuthResult(-EACCES);
	}

	auto status = verify.get_http_status();
	ldpp_dout(dpp, 20) << fmt::format("fetch '{}' status {}", query_url, status) << dendl;

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
		ldpp_dout(dpp, 5) << fmt::format("fetch '{}' unknown status {}", query_url, status) << dendl;
		return HandoffAuthResult(-EACCES);
	}

	return HandoffAuthResult("testid"); // XXX!!!
	// return HandoffAuthResult(-EACCES);
  };

} /* namespace rgw */
