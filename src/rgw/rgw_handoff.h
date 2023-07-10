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

/**
 * @brief Return type of the HandoffHelper auth() method.
 *
 * Encapsulates either the return values we need to continue on successful
 * authentication, or a failure code.
 */
class HandoffAuthResult {
	std::string userid_ = "";
	int errorcode_ = 0;
	std::string message_ = "";
	bool is_err_ = false;

public:
	/// @brief Construct a success-type result. \p message is
	/// human-readable status.
	HandoffAuthResult(const std::string& userid, const std::string& message) : userid_{userid}, message_{message}, is_err_{false} {};
	/// @brief Construct a failure-type result with an error code.
	/// \p message is human-readable status.
	HandoffAuthResult(int errorcode, const std::string& message) : errorcode_{errorcode}, message_{message}, is_err_{true} {};

	bool is_err() { return is_err_; }
	bool is_ok() { return !is_err_; }
	int code() { return errorcode_; }
	std::string message() { return message_; }

	/// @brief Return the user ID for a success result. Throw EACCES on
	/// failure.
	///
	/// This is to catch erroneous use of userid(). It will probably get
	/// thrown all the way up to rgw::auth::Strategy::authenticate().
	std::string userid() {
		if (is_err()) {
			throw -EACCES;
		}
		return userid_;
	}

	std::string to_string() {
		if (is_err()) {
			return fmt::format("error={} message={}", errorcode_, message_);
		} else {
			return fmt::format("userid='{}' message={}", userid_, message_);
		}
	}
};

/**
 * @brief Support class for 'handoff' authentication.
 *
 * Used by rgw::auth::s3::HandoffEngine to implement authentication via an
 * external REST service.
 */
class HandoffHelper {

public:

	HandoffHelper() {}
	~HandoffHelper() {}

	/**
	 * @brief Initialise any long-lived state for this engine.
	 * @param cct Pointer to the Ceph context
	 * @return 0 on success, otherwise failure.
	 *
	 * Currently a placeholder, there's no long-lived state at this time.
	 */
	int init(CephContext *const cct);

	/**
	 * @brief Authenticate the transaction using the Handoff engine.
	 * @param dpp Debug prefix provider. Points to the Ceph context.
	 * @param session_token Unused by Handoff.
	 * @param access_key_id The S3 access key.
	 * @param string_to_sign The canonicalised S3 signature input.
	 * @param signature The transaction signature provided by the user.
	 * @param s Pointer to the req_state.
	 * @param y An optional yield token.
	 * @return A HandofAuthResult encapsulating a return error code and
	 * any parameters necessary to continue processing the request, e.g.
	 * the uid associated with the access key.
	 *
	 * Perform request authentication via the external authenticator.
	 *
	 * - Extract the Authorization header from the environment. This will
	 *   be necessary to validate a v4 signature because we need some
	 *   fields (date, region, service, request type) for step 2 of the
	 *   signature process.
	 *
	 *
	 * - Construct a JSON payload for the authenticator in the prescribed
	 *   format.
	 *
	 * - Fetch the authenticator URI from the context. This can't be
	 *   trivially cached, as we want to support changing it at runtime.
	 *   However, future enhancements may perform some time-based caching
	 *   if performance profiling shows this is a problem.
	 *
	 * - Append '/verify' to the authenticator URI.
	 *
	 * - Send the request to the authenticator using an
	 *   RGWHTTPTransceiver. We need the transceiver version as we'll be
	 *   both sending a POST request and reading the response body. (This
	 *   is cribbed from the Keystone code.)
	 *
	 * - If the request send itself fails (we'll handle failure return
	 *   codes presently), return EACCES immediately.
	 *
	 * - Parse the JSON response to obtain the human-readable message
	 *   field, even if the authentication response is a failure.
	 *
	 * - If the request returned 200, return success.
	 *
	 * - If the request returned 401, return ERR_SIGNATURE_NO_MATCH.
	 *
	 * - If the request returned 404, return ERR_INVALID_ACCESS_KEY.
	 *
	 * - If the request returned any other code, return EACCES.
	 */
	HandoffAuthResult auth(const DoutPrefixProvider *dpp,
		const std::string_view& session_token,
		const std::string_view& access_key_id,
		const std::string_view& string_to_sign,
		const std::string_view& signature,
		const req_state* const s,
		optional_yield y);
};

} /* namespace rgw */

#endif /* RGW_HANDOFF_H */
