// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef RGW_HANDOFF_H
#define RGW_HANDOFF_H

#include "acconfig.h"

#include <fmt/format.h>
#include <functional>
#include <iosfwd>
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
  HandoffAuthResult(const std::string& userid, const std::string& message)
      : userid_ { userid }
      , message_ { message }
      , is_err_ { false } {};
  /// @brief Construct a failure-type result with an error code.
  /// \p message is human-readable status.
  HandoffAuthResult(int errorcode, const std::string& message)
      : errorcode_ { errorcode }
      , message_ { message }
      , is_err_ { true } {};

  bool is_err() const noexcept { return is_err_; }
  bool is_ok() const noexcept { return !is_err_; }
  int code() const noexcept { return errorcode_; }
  std::string message() const noexcept { return message_; }

  /// @brief Return the user ID for a success result. Throw EACCES on
  /// failure.
  ///
  /// This is to catch erroneous use of userid(). It will probably get
  /// thrown all the way up to rgw::auth::Strategy::authenticate().
  std::string userid() const
  {
    if (is_err()) {
      throw -EACCES;
    }
    return userid_;
  }

  std::string to_string() const noexcept
  {
    if (is_err()) {
      return fmt::format("error={} message={}", errorcode_, message_);
    } else {
      return fmt::format("userid='{}' message={}", userid_, message_);
    }
  }
};

class HandoffVerifyResult {
  int result_;
  long http_code_;
  std::string query_url_;

public:
  HandoffVerifyResult()
      : result_ { -1 }
      , http_code_ { 0 }
      , query_url_ { "" }
  {
  }
  HandoffVerifyResult(int result, long http_code, std::string query_url = "")
      : result_ { result }
      , http_code_ { http_code }
      , query_url_ { query_url }
  {
  }
  // No copy or copy-assignment.
  HandoffVerifyResult(HandoffVerifyResult& other) = delete;
  HandoffVerifyResult& operator=(HandoffVerifyResult& other) = delete;
  // Trivial move and move-assignment.
  HandoffVerifyResult(HandoffVerifyResult&& other) = default;
  HandoffVerifyResult& operator=(HandoffVerifyResult&& other) = default;

  int result() const noexcept { return result_; }
  long http_code() const noexcept { return http_code_; }
  std::string query_url() const noexcept { return query_url_; }
};

class EAKParameters {

private:
  bool valid_;
  std::string method_;
  std::string bucket_name_;
  std::string object_key_name_;

  void valid_check() const
  {
    if (!valid()) {
      throw new std::runtime_error("EAKParamters not valid");
    }
  }

public:
  EAKParameters(const DoutPrefixProvider* dpp, const req_state* s) noexcept;

  // Standard copies and moves are fine.
  EAKParameters(EAKParameters& other) = default;
  EAKParameters& operator=(EAKParameters& other) = default;
  EAKParameters(EAKParameters&& other) = default;
  EAKParameters& operator=(EAKParameters&& other) = default;

  /**
   * @brief Return the validity of this EAKParameters object.
   *
   * If at construction time the request was well-formed and contained
   * sufficient information to be used in an EAK request to the Authenticator,
   * return true.
   *
   * Otherwise, return false.
   *
   * @return true The request can be used as the source of an EAK
   * authentication operation.
   * @return false The request cannot be used.
   */
  bool valid() const noexcept
  {
    return valid_;
  }
  /**
   * @brief Return the HTTP method for a valid request. Throw if valid() is
   * false.
   *
   * @return std::string The method.
   * @throw std::runtime_error if !valid().
   */
  std::string method() const
  {
    valid_check();
    return method_;
  }
  /**
   * @brief Return the bucket name for a valid request. Throw if valid() is
   * false.
   *
   * @return std::string The bucket name.
   * @throw std::runtime_error if !valid().
   */
  std::string bucket_name() const
  {
    valid_check();
    return bucket_name_;
  }
  /**
   * @brief Return the object key name for a valid request. Throw if valid()
   * is false.
   *
   * @return std::string The object key name.
   * @throw std::runtime_error if !valid().
   */
  std::string object_key_name() const
  {
    valid_check();
    return object_key_name_;
  }

  /**
   * @brief Convert this EAKParameters object to string form.
   *
   * @return std::string A string representation of the object. Works fine for
   * objects in the invalid state; this call is always safe.
   */
  std::string to_string() const noexcept
  {
    if (valid()) {
      return fmt::format("EAKParameters(method={},bucket={},key={})", method(), bucket_name(), object_key_name());
    } else {
      return "EAKParameters(INVALID)";
    }
  }

  /// Used to implement streaming.
  friend std::ostream& operator<<(std::ostream& os, const EAKParameters& ep);
};

std::ostream& operator<<(std::ostream& os, const EAKParameters& ep);

/**
 * @brief Support class for 'handoff' authentication.
 *
 * Used by rgw::auth::s3::HandoffEngine to implement authentication via an
 * external REST service.
 */
class HandoffHelper {

public:
  // Signature of the alternative verify function,  used only for testing.
  using VerifyFunc = std::function<HandoffVerifyResult(const DoutPrefixProvider*, const std::string&, ceph::bufferlist*, optional_yield)>;

private:
  const std::optional<VerifyFunc> verify_func_;
  rgw::sal::Store* store_;

public:
  HandoffHelper() { }
  /**
   * @brief Construct a new Handoff Helper object with an alternative callout
   * mechanism. Used by test harnesses.
   *
   * @param v A function to replace the HTTP client callout. This must mimic
   * the inputs and outputs of the \p verify_standard() function.
   */
  HandoffHelper(VerifyFunc v)
      : verify_func_ { v }
  {
  }
  ~HandoffHelper() { }

  /**
   * @brief Initialise any long-lived state for this engine.
   * @param cct Pointer to the Ceph context.
   * @param store Pointer to the sal::Store object.
   * @return 0 on success, otherwise failure.
   *
   * Currently a placeholder, there's no long-lived state at this time.
   */
  int init(CephContext* const cct, rgw::sal::Store* store);

  /**
   * @brief Authenticate the transaction using the Handoff engine.
   * @param dpp Debug prefix provider. Points to the Ceph context.
   * @param session_token Unused by Handoff.
   * @param access_key_id The S3 access key.
   * @param string_to_sign The canonicalised S3 signature input.
   * @param signature The transaction signature provided by the user.
   * @param s Pointer to the req_state.
   * @param y An optional yield token.
   * @return A HandofAuthResult encapsulating a return error code and any
   * parameters necessary to continue processing the request, e.g. the uid
   * associated with the access key.
   *
   * Perform request authentication via the external authenticator.
   *
   * There is a mechanism for a test harness to replace the HTTP client
   * portion of this function. Here we'll assume we're using the HTTP client
   * to authenticate.
   *
   * - Extract the Authorization header from the environment. This will be
   *   necessary to validate a v4 signature because we need some fields (date,
   *   region, service, request type) for step 2 of the signature process.
   *
   * - If the header indicates AWS Signature V2 authentication, but V2 is
   *   disabled via configuration, return a failure immediately.
   *
   * - Construct a JSON payload for the authenticator in the prescribed
   *   format.
   *
   * - At this point, call a test harness to perform authentication if one is
   *   configured. Otherwise...
   *
   * - Fetch the authenticator URI from the context. This can't be trivially
   *   cached, as we want to support changing it at runtime. However, future
   *   enhancements may perform some time-based caching if performance
   *   profiling shows this is a problem.
   *
   * - Append '/verify' to the authenticator URI.
   *
   * - Send the request to the authenticator using an RGWHTTPTransceiver. We
   *   need the transceiver version as we'll be both sending a POST request
   *   and reading the response body. (This is cribbed from the Keystone
   *   code.)
   *
   * - If the request send itself fails (we'll handle failure return codes
   *   presently), return EACCES immediately.
   *
   * - Parse the JSON response to obtain the human-readable message field,
   *   even if the authentication response is a failure.
   *
   * - If the request returned 200, return success.
   *
   * - If the request returned 401, return ERR_SIGNATURE_NO_MATCH.
   *
   * - If the request returned 404, return ERR_INVALID_ACCESS_KEY.
   *
   * - If the request returned any other code, return EACCES.
   */
  HandoffAuthResult auth(const DoutPrefixProvider* dpp,
      const std::string_view& session_token,
      const std::string_view& access_key_id,
      const std::string_view& string_to_sign,
      const std::string_view& signature,
      const req_state* const s,
      optional_yield y);

  /**
   * @brief Construct an Authorization header from the parsed query string
   * parameters.
   *
   * The Authorization header is a fairly concise way of sending a bunch of
   * bundled parameters to the Authenticator. So if (as would be the case with
   * a presigned URL) we don't get an Authorization header, see if we can
   * synthesize one from the query parameters.
   *
   * This function first has to distinguish between v2 and v4 parameters
   * (normally v2 if no region is supplied, defaulting to us-east-1). Then it
   * has to parse the completely distinct parameters for each version into a
   * v2 or v4 Authorization: header, via synthesize_v2_header() or
   * synthesize_v4_header() respectively.
   *
   * @param dpp DoutPrefixProvider.
   * @param s The request.
   * @return std::optional<std::string> The header on success, or std::nullopt
   * on any failure.
   */
  std::optional<std::string> synthesize_auth_header(
      const DoutPrefixProvider* dpp,
      const req_state* s);

  /**
   * @brief Assuming an already-parsed (via synthesize_auth_header) presigned
   * header URL, check that the given expiry time has not expired. Note that
   * in v17.2.6, this won't get called - RGW checks the expiry time before
   * even calling our authentication engine.
   *
   * Fail closed - if we can't parse the parameters to check, assume we're not
   * authenticated.
   *
   * The fields are version-specific. For the v2-ish URLs (no region
   * specified), we're given an expiry unix time to compare against. For the
   * v4-type URLs (region specified), we're given a start time and a delta in
   * seconds.
   *
   * @param dpp DoutPrefixProvider.
   * @param s The request.
   * @param now The current UNIX time (seconds since the epoch).
   * @return true The request has not expired
   * @return false The request has expired, or a check was not possible
   */
  bool valid_presigned_time(const DoutPrefixProvider* dpp, const req_state* s, time_t now);
};

} /* namespace rgw */

#endif /* RGW_HANDOFF_H */
