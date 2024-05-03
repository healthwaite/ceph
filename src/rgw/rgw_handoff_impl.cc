/**
 * @file rgw_handoff_impl.cc
 * @author André Lucas (alucas@akamai.com)
 * @brief Implementation for rgw::HandoffHelperImpl.
 * @version 0.1
 * @date 2023-11-10
 *
 * @copyright Copyright (c) 2023
 *
 * PIMPL implementation class for HandoffHelper.
 *
 * HandoffHelper simply wraps HandoffHelperImpl.
 *
 * Exists because HandoffHelper is created in rgw_rest_s3.cc, so has to be
 * #include'd. The include ends up being transient (via rgw_rest_s3.h), so we
 * end up including all the gRPC headers for almost every file. This makes it
 * slower, and breaks some stuff.
 *
 * Also it has the usual PIMPL benefits - making small changes here doesn't
 * transitively cause mass rebuilds, even if we change our header file.
 */

/* References:
 *
 * AWS Signature Version 4 documentation:
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
 *
 * AWS Signature Version 2 documentation:
 * https://docs.aws.amazon.com/AmazonS3/latest/userguide/auth-request-sig-v2.html
 */

#include "rgw_handoff_impl.h"

#include <boost/algorithm/string.hpp>
#include <cerrno>
#include <cstring>
#include <fmt/format.h>
#include <iostream>
#include <mutex>
#include <optional>
#include <rgw_handoff.h>
#include <string>
#include <string_view>

#include <time.h>

#include "absl/strings/numbers.h"
#include "absl/time/time.h"
#include "authenticator/v1/authenticator.pb.h"
#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_b64.h"
#include "rgw/rgw_client_io.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_http_client.h"

// These are 'standard' protobufs for the 'Richer error model'
// (https://grpc.io/docs/guides/error/).
#include "google/rpc/error_details.pb.h"
#include "google/rpc/status.pb.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

namespace ba = boost::algorithm;

namespace rgw {

/****************************************************************************/

/**
 * @brief Construct a new AuthorizationParameters object from an in-flight
 * request.
 *
 * Given a request, read the parameters required for an authorization-enhanced
 * request to the Authenticator.
 *
 * The HTTP method, the bucket name, and optionally the object key name will
 * be extracted from the HTTP request parameters.
 *
 * In practice this amounts to an early invocation of parts of
 * RGWHandler_Lib::init_from_header(), where we need some of this information
 * in order to properly authenticate the request.
 *
 * Doing work on an unauthenticated request is risky. It introduces potential
 * security problems. For example, we've done nothing to validate the bucket
 * and object key names yet, though they will at least have been URL decoded.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request (const).
 */
AuthorizationParameters::AuthorizationParameters(const DoutPrefixProvider* dpp_in, const req_state* s) noexcept
{
  auto hdpp = HandoffDoutPrefixPipe(*dpp_in, "AuthorizationParameters");
  auto dpp = &hdpp;
  valid_ = false;

  ceph_assert(s != nullptr); // Give a helpful error to unit tests.

  // Method should be set in the request.
  if (!s->info.method || *(s->info.method) == 0) {
    ldpp_dout(dpp, 0) << "Invalid request method" << dendl;
    return;
  }
  method_ = s->info.method;

  std::string req;
  std::string first;
  const char* req_name = s->relative_uri.c_str();

  // We expect the request portion including parameters, starting with the
  // leading slash. If it's not, we need to abort as the request is malformed.
  if (*req_name != '/') {
    ldpp_dout(dpp, 0) << "Invalid relative_uri string" << dendl;
    return;
  }
  req_name++;

  // Save all the HTTP headers starting with 'x_amz_'. Do this before the
  // first valid exit.
  ceph_assert(s->cio != nullptr); // Give a helpful error to unit tests.
  for (const auto& kv : s->cio->get_env().get_map()) {
    std::string key = kv.first;
    // HTTP headers are uppercased and have hyphens replaced with underscores.
    if (ba::starts_with(key, "HTTP_X_AMZ_")) {
      key = key.substr(5);
      ba::replace_all(key, "_", "-");
      ba::to_lower(key);
      http_headers_.emplace(key, kv.second);
    }
  }

  // This is the path element of the URI, up to the '?'.
  http_request_path_ = s->info.request_uri;

  // Save all the HTTP URI query parameters. Do this before the first valid
  // exit.
  for (const auto& kv : s->info.args.get_params()) {
    http_query_params_.emplace(kv.first, kv.second);
  }

  // An empty request portion isn't that useful to authorization, but is valid
  // in general use - it's generated by e.g. 's3cmd ls' with no options. We'll
  // return an object that has very little information, but _is_ valid.
  //
  if (*req_name == 0) {
    ldpp_dout(dpp, 0) << "No query string information available" << dendl;
    valid_ = true;
    return;
  }

  // We're relying on the first parameter being the bucket name, even if the
  // original URL is of the form http://bucket.host.name/objectkey (as is
  // preferred by s3cmd).
  //
  // This canonicalisation step is performed by RGWREST::preprocess(), in
  // v17.2.6 it's in rgw_rest.cc near line 2152: If the domain name appears to
  // be a prefix on a name we recognise (e.g. bucket.host.name for a server
  // with name host.name), we prepend "bucket" to the list of parameters.
  //
  // This is super helpful as it means we don't have to handle the special
  // case.

  req = std::string(req_name);
  size_t pos = req.find('/');
  if (pos != std::string::npos) {
    bucket_name_ = req.substr(0, pos);
  } else {
    bucket_name_ = req;
  }

  // The object key name can legitimately be empty.
  if (pos != std::string::npos && req.size() > pos) {
    object_key_name_ = req.substr(pos + 1);
  }

  valid_ = true;
}

std::string AuthorizationParameters::to_string() const noexcept
{
  if (!valid()) {
    return "AuthorizationParameters(INVALID)";

  } else {
    std::string hdr;
    if (http_headers_.empty()) {
      hdr = "none";
    } else {
      std::vector<std::string> h;
      for (const auto& kv : http_headers_) {
        h.emplace_back(fmt::format(FMT_STRING("{}={},"), kv.first, kv.second));
      }
      hdr = fmt::format(FMT_STRING("[{}]"), fmt::join(h, ","));
    }
    std::string qparam;
    if (http_query_params_.empty()) {
      qparam = "none";
    } else {
      std::vector<std::string> q;
      for (const auto& kv : http_query_params_) {
        q.emplace_back(fmt::format(FMT_STRING("{}={}"), kv.first, kv.second));
      }
      qparam = fmt::format(FMT_STRING("[{}]"), fmt::join(q, ","));
    }
    return fmt::format(
        FMT_STRING("AuthorizationParameters(method={},bucket={},key_present={},request_path={},http_headers={},query_param={})"),
        method(),
        bucket_name(),
        object_key_name().empty() ? "false" : "true",
        http_request_path(),
        hdr,
        qparam);
  }
}

std::ostream& operator<<(std::ostream& os, const AuthorizationParameters& ep)
{
  os << ep.to_string();
  return os;
}

/****************************************************************************/

/****************************************************************************
 *
 * AuthServiceClient - gRPC client wrapper for rgw/auth/v1/AuthService.
 *
 ****************************************************************************/

HandoffAuthResult AuthServiceClient::Auth(const AuthenticateRESTRequest& req)
{
  ::grpc::ClientContext context;
  AuthenticateRESTResponse resp;

  ::grpc::Status status = stub_->AuthenticateREST(&context, req, &resp);

  using namespace authenticator::v1;

  if (status.ok()) {
    return HandoffAuthResult(resp.user_id(), status.error_message());
  }
  // Error conditions are returned via the Richer error model
  // (https://grpc.io/docs/guides/error/). Create a google::rpc::Status
  // message.
  auto error_details = status.error_details();
  if (error_details.empty()) {
    // There are no error details, so there can't be an S3ErrorDetails
    // message, so we assume this is related to the RPC itself, not the
    // authentication. This gets a TRANSPORT_ERROR.
    return HandoffAuthResult(-EACCES, status.error_message(), HandoffAuthResult::error_type::TRANSPORT_ERROR);
  }
  ::google::rpc::Status s;
  if (!s.ParseFromString(error_details)) {
    return HandoffAuthResult(-EACCES, "failed to deserialize gRPC error_details, error message follows: " + status.error_message(), HandoffAuthResult::error_type::INTERNAL_ERROR);
  }
  // Loop through the detail field (repeated Any) and look for our
  // S3ErrorDetails message.
  for (auto& detail : s.details()) {
    S3ErrorDetails s3_details;
    if (detail.UnpackTo(&s3_details)) {
      return _translate_authenticator_error_code(s3_details.type(), s3_details.http_status_code(), status.error_message());
    }
  }
  // There was no S3ErrorDetails message, so assume the error was related to
  // the RPC itself, not the authentication, and that in some future version
  // of gRPC the transport errors use the Richer error model. (Stranger things
  // have happened.) This gets a TRANSPORT_ERROR, as above.
  return HandoffAuthResult(-EACCES, "S3ErrorDetails not found, error message follows: " + status.error_message(), HandoffAuthResult::error_type::TRANSPORT_ERROR);
}

AuthServiceClient::GetSigningKeyResult
AuthServiceClient::GetSigningKey(const GetSigningKeyRequest req)
{
  ::grpc::ClientContext context;
  GetSigningKeyResponse resp;

  ::grpc::Status status = stub_->GetSigningKey(&context, req, &resp);
  if (status.ok()) {
    auto key = resp.signing_key();
    std::vector<uint8_t> kvec;
    std::copy(key.begin(), key.end(), std::back_inserter(kvec));
    return GetSigningKeyResult(kvec);
  }
  return GetSigningKeyResult(status.error_message());
}

using err_type = ::authenticator::v1::S3ErrorDetails_Type;

// We can't statically initialise a map, so initialise a list and allocate a
// map on first use in _translate_authenticator_error_code().
struct HandoffAuthResultMapping {
  err_type auth_type;
  int rgw_error_code;
};

static HandoffAuthResultMapping auth_list[] = {
  { err_type::S3ErrorDetails_Type_TYPE_ACCESS_DENIED, EACCES },
  { err_type::S3ErrorDetails_Type_TYPE_AUTHORIZATION_HEADER_MALFORMED, ERR_INVALID_REQUEST },
  { err_type::S3ErrorDetails_Type_TYPE_EXPIRED_TOKEN, EACCES },
  { err_type::S3ErrorDetails_Type_TYPE_INTERNAL_ERROR, ERR_INTERNAL_ERROR },
  { err_type::S3ErrorDetails_Type_TYPE_INVALID_ACCESS_KEY_ID, ERR_INVALID_ACCESS_KEY },
  { err_type::S3ErrorDetails_Type_TYPE_INVALID_REQUEST, EINVAL },
  { err_type::S3ErrorDetails_Type_TYPE_INVALID_SECURITY, EINVAL },
  { err_type::S3ErrorDetails_Type_TYPE_INVALID_TOKEN, ERR_INVALID_IDENTITY_TOKEN },
  { err_type::S3ErrorDetails_Type_TYPE_INVALID_URI, ERR_INVALID_REQUEST },
  { err_type::S3ErrorDetails_Type_TYPE_METHOD_NOT_ALLOWED, ERR_METHOD_NOT_ALLOWED },
  { err_type::S3ErrorDetails_Type_TYPE_MISSING_SECURITY_HEADER, ERR_INVALID_REQUEST },
  { err_type::S3ErrorDetails_Type_TYPE_REQUEST_TIME_TOO_SKEWED, ERR_REQUEST_TIME_SKEWED },
  { err_type::S3ErrorDetails_Type_TYPE_SIGNATURE_DOES_NOT_MATCH, ERR_SIGNATURE_NO_MATCH },
  { err_type::S3ErrorDetails_Type_TYPE_TOKEN_REFRESH_REQUIRED, ERR_INVALID_REQUEST }
};

static std::map<err_type, int> auth_map;

HandoffAuthResult AuthServiceClient::_translate_authenticator_error_code(
    ::authenticator::v1::S3ErrorDetails_Type auth_type,
    int32_t auth_http_status_code,
    const std::string& message)
{
  static std::once_flag map_init;
  std::call_once(map_init, []() {
    for (const auto& al : auth_list) {
      auth_map[al.auth_type] = al.rgw_error_code;
    }
  });
  auto srch = auth_map.find(auth_type);
  if (srch != auth_map.end()) {
    // Return an entry in the map directly.
    return HandoffAuthResult(srch->second, message, HandoffAuthResult::error_type::AUTH_ERROR);
  } else {
    // With no direct mapping, return an RGW error with the HTTP status code
    // indicated by the Authenticator. This is far from perfect; we're not
    // giving the user a good experience here but we need to return something.
    //
    switch (auth_http_status_code) {
    case 400:
      return HandoffAuthResult(EINVAL, message, HandoffAuthResult::error_type::AUTH_ERROR);
    case 404:
      return HandoffAuthResult(ERR_NOT_FOUND, message, HandoffAuthResult::error_type::AUTH_ERROR);
    case 403:
    default:
      return HandoffAuthResult(EACCES, message, HandoffAuthResult::error_type::AUTH_ERROR);
    }
  }
}

/****************************************************************************/

/**
 * @brief Create an AWS v2 authorization header from the request's URL
 * parameters.
 *
 * The v2 header form is generated by `s3cmd signurl` and `aws s3 presign`
 * when either no region is provided, or the region is us-east-1. It is
 * simply:
 *
 * ```
 *   AWS <accesskeyid>:<signature>
 * ```
 *
 * Everything else required to check the signature will be provided to the
 * Authenticator in StringToSign.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request state.
 * @return std::optional<std::string> On failure, std::nullopt. On success,
 * the value for the Authorization: header.
 */
static std::optional<std::string> synthesize_v2_header(const DoutPrefixProvider* dpp, const req_state* s)
{
  auto& infomap = s->info.args;
  auto maybe_credential = infomap.get_optional("AWSAccessKeyId");
  if (!maybe_credential) {
    ldpp_dout(dpp, 0) << "Missing AWSAccessKeyId parameter" << dendl;
  }
  auto maybe_signature = infomap.get_optional("Signature");
  if (!maybe_signature) {
    ldpp_dout(dpp, 0) << "Missing Signature parameter" << dendl;
  }
  if (!(maybe_credential && maybe_signature)) {
    return std::nullopt;
  }
  return std::make_optional(fmt::format("AWS {}:{}",
      *maybe_credential, *maybe_signature));
}

/**
 * @brief Create an AWS v4 authorization header from the request's URL
 * parameters.
 *
 * The V4 header form required the (long) credentials:
 *
 * ```
 *    <accesskeyid>/<region>/s3/aws_request
 * ```
 *
 * The SignedHeaders value, and the Signature value. These are formatted into:
 *
 * ```
 *    AWS4-HMAC-SHA256 Credential=<credentials>, SignedHeaders=<signedheader>, Signature=<signature>
 * ```
 *
 * We don't support signature v4A (ECDSA) at this time.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request state.
 * @return std::optional<std::string> On failure, std::nullopt. On success,
 * the value for the Authorization: header.
 */
static std::optional<std::string> synthesize_v4_header(const DoutPrefixProvider* dpp, const req_state* s)
{
  auto& infomap = s->info.args;

  // Params starting with 'X-Amz' are lowercased.
  auto maybe_credential = infomap.get_optional("x-amz-credential");
  if (!maybe_credential) {
    ldpp_dout(dpp, 0) << "Missing x-amz-credential parameter" << dendl;
  }
  auto maybe_signedheaders = infomap.get_optional("x-amz-signedheaders");
  if (!maybe_signedheaders) {
    ldpp_dout(dpp, 0) << "Missing x-amz-signedheaders parameter" << dendl;
  }
  auto maybe_signature = infomap.get_optional("x-amz-signature");
  if (!maybe_signature) {
    ldpp_dout(dpp, 0) << "Missing x-amz-signature parameter" << dendl;
  }
  if (!(maybe_credential && maybe_signedheaders && maybe_signature)) {
    return std::nullopt;
  }
  return std::make_optional(fmt::format("AWS4-HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}",
      *maybe_credential, *maybe_signedheaders, *maybe_signature));
}

/****************************************************************************
 *
 * HandoffHelperImpl
 *
 ****************************************************************************/

int HandoffHelperImpl::init(CephContext* const cct, rgw::sal::Driver* store, const std::string& grpc_uri)
{
  store_ = store;

  ceph_assert(cct != nullptr);
  config_obs_.init(cct);

  // Set up some state variables based on configuration. Most of these are not
  // runtime-alterable.

  ldout(cct, 1) << "HandoffHelperImpl::init()" << dendl;
  grpc_mode_ = true;
  // Production calls to this function will have grpc_uri empty, so we'll
  // fetch configuration. Unit tests will pass a URI.
  auto uri = grpc_uri.empty() ? cct->_conf->rgw_handoff_grpc_uri : grpc_uri;

  // Will use rgw_handoff_grpc_uri, which is runtime-alterable.
  // set_channel_uri() will fetch default channel args if none have been set
  // beforehand.
  if (!set_channel_uri(cct, uri)) {
    // This is unlikely, but no gRPC channel in gRPC mode is a fatal error.
    // Note that this won't attempt to connect! That's done lazily on first
    // use. This will just attempt to create the channel object.
    throw new std::runtime_error("Failed to create initial gRPC channel");
  }

  // rgw_handoff_enable_presigned_expiry_check is not runtime-alterable.
  presigned_expiry_check_ = cct->_conf->rgw_handoff_enable_presigned_expiry_check;
  ldout(cct, 5) << fmt::format(FMT_STRING("HandoffHelperImpl::init(): Presigned URL expiry check {}"), (presigned_expiry_check_ ? "enabled" : "disabled")) << dendl;

  // rgw_handoff_enable_signature_v2 is runtime-alterable.
  set_signature_v2(cct, cct->_conf->rgw_handoff_enable_signature_v2);

  // rgw_handoff_enable_chunked_upload is runtime-alterable.
  set_chunked_upload_mode(cct, cct->_conf->rgw_handoff_enable_chunked_upload);

  // The authparam mode is runtime-alterable.
  set_authorization_mode(cct, config_obs_.get_authorization_mode(cct->_conf));

  return 0; // Return value is ignored.
}

grpc::ChannelArguments HandoffHelperImpl::get_default_channel_args(CephContext* const cct)
{
  grpc::ChannelArguments args;

  // Set our default backoff parameters. These are runtime-alterable.
  args.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, cct->_conf->rgw_handoff_grpc_arg_initial_reconnect_backoff_ms);
  args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, cct->_conf->rgw_handoff_grpc_arg_max_reconnect_backoff_ms);
  args.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, cct->_conf->rgw_handoff_grpc_arg_min_reconnect_backoff_ms);
  ldout(cct, 20) << fmt::format(FMT_STRING("HandoffHelperImpl::{}: reconnect_backoff(ms): initial/min/max={}/{}/{}"),
      __func__,
      cct->_conf->rgw_handoff_grpc_arg_initial_reconnect_backoff_ms,
      cct->_conf->rgw_handoff_grpc_arg_min_reconnect_backoff_ms,
      cct->_conf->rgw_handoff_grpc_arg_max_reconnect_backoff_ms)
                 << dendl;

  return grpc::ChannelArguments();
}

bool HandoffHelperImpl::set_channel_uri(CephContext* const cct, const std::string& new_uri)
{
  ldout(cct, 5) << fmt::format(FMT_STRING("HandoffHelperImpl::set_channel_uri({})"), new_uri) << dendl;
  std::unique_lock<chan_lock_t> g(m_channel_);
  if (!channel_args_) {
    auto args = get_default_channel_args(cct);
    // Don't use set_channel_args(), which takes lock m_channel_.
    channel_args_ = std::make_optional(std::move(args));
  }
  // XXX grpc::InsecureChannelCredentials()...
  auto new_channel = grpc::CreateCustomChannel(new_uri, grpc::InsecureChannelCredentials(), *channel_args_);
  if (!new_channel) {
    ldout(cct, 0) << fmt::format(FMT_STRING("HandoffHelperImpl::set_channel_uri(): ERROR: Failed to create new gRPC channel for URI {}"), new_uri) << dendl;
    return false;
  } else {
    ldout(cct, 1) << fmt::format(FMT_STRING("HandoffHelperImpl::set_channel_uri({}) success"), new_uri) << dendl;
    channel_ = std::move(new_channel);
    channel_uri_ = new_uri;
    return true;
  }
}

void HandoffHelperImpl::set_signature_v2(CephContext* const cct, bool enabled)
{
  ldout(cct, 1) << fmt::format(FMT_STRING("HandoffHelperImpl: set_signature_v2({})"), (enabled ? "true" : "false")) << dendl;
  std::unique_lock<std::shared_mutex> g(m_config_);
  enable_signature_v2_ = enabled;
}

void HandoffHelperImpl::set_chunked_upload_mode(CephContext* const cct, bool enabled)
{
  ldout(cct, 1) << fmt::format(FMT_STRING("HandoffHelperImpl::set_chunked_upload_mode({})"), (enabled ? "true" : "false")) << dendl;
  std::unique_lock<std::shared_mutex> g(m_config_);
  enable_chunked_upload_ = enabled;
}

std::optional<std::string> HandoffHelperImpl::synthesize_auth_header(
    const DoutPrefixProvider* dpp,
    const req_state* s)
{
  if (s->info.args.exists("AWSAccessKeyId")) {
    return synthesize_v2_header(dpp, s);
  }
  // Params starting with 'X-Amz' are lowercased.
  if (s->info.args.exists("x-amz-credential")) {
    return synthesize_v4_header(dpp, s);
  }
  return std::nullopt;
}

/**
 * @brief Return a string representation of an AuthorizationMode enum value.
 *
 * @param mode the Authorization mode.
 * @return std::string A string representation of \p mode.
 */
static std::string authorization_mode_to_string(AuthParamMode mode)
{
  switch (mode) {
  case AuthParamMode::ALWAYS:
    return "ALWAYS";
  case AuthParamMode::WITHTOKEN:
    return "WITHTOKEN";
  case AuthParamMode::NEVER:
    return "NEVER";
  }
  return "UNKNOWN";
}

void HandoffHelperImpl::set_authorization_mode(CephContext* const cct, AuthParamMode mode)
{
  std::unique_lock<std::shared_mutex> g(m_config_);
  ldout(cct, 1) << fmt::format(FMT_STRING("HandoffHelperImpl: set_authorization_mode({})"), authorization_mode_to_string(mode)) << dendl;
  authorization_mode_ = mode;
}

/**
 * @brief Deduce the AWS V4 presigned URL expiry time.
 *
 * The V4 expiry calculation is more complex than V2. The request time is
 * provided in the x-amz-date parameter, and the expiry time delta is provided
 * in the x-amz-expires parameter. We have to parse the x-amz-date string into
 * a time, then add the delta to get the expiry time.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request.
 * @return std::optional<time_t> The expiry time as a time_t value, or nullopt
 * if the value could not be deduced.
 */
static std::optional<time_t> get_v4_presigned_expiry_time(const DoutPrefixProvider* dpp, const req_state* s) noexcept
{
  auto& argmap = s->info.args;
  auto maybe_date = argmap.get_optional("x-amz-date");
  if (!maybe_date) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("{}:  Missing x-amz-date parameter"), __func__) << dendl;
  }
  auto maybe_expires_delta = argmap.get_optional("x-amz-expires");
  if (!maybe_expires_delta) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("{}: Missing x-amz-expires parameter"), __func__) << dendl;
  }
  if (!(maybe_date && maybe_expires_delta)) {
    return std::nullopt;
  }

  std::string date = std::move(*maybe_date);
  std::string delta = std::move(*maybe_expires_delta);

  absl::Time param_time;
  std::string err;
  // absl::ParseTime()'s format has some extensions to strftime(3). The %E4Y is
  // a 4-digit year, %ET is the 'T' separator, and %Ez is the timezone spec
  // which in Abseil can be the 'Z' indicating UTC.
  if (!absl::ParseTime("%E4Y%m%d%ET%H%M%S%Ez", date, &param_time, &err)) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("{}: Failed to parse x-amz-date time '{}': {}"), __func__, date, err) << dendl;
    return std::nullopt;
  }
  int delta_seconds = 0;
  if (!absl::SimpleAtoi(delta, &delta_seconds)) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("{}: Failed to parse int from x-amz-expires='{}'"), __func__, delta) << dendl;
  }
  auto expiry_time = param_time + absl::Seconds(delta_seconds);
  auto expiry = absl::ToTimeT(expiry_time);
  ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("{}: x-amz-date {}, delta {} -> expiry time {}"), __func__, date, delta, expiry) << dendl;
  return std::make_optional(expiry);
}

/**
 * @brief Extract the AWS V2 presigned URL expiry time.
 *
 * V2 expiry times are really straightforward - they're just a UNIX timestamp
 * after which the request is invalid.
 *
 * @param dpp DoutPrefixProvider.
 * @param s The request.
 * @return std::optional<time_t> The expiry time as a time_t value, or nullopt
 * if the value could not be extracted.
 */
static std::optional<time_t> get_v2_presigned_expiry_time(const DoutPrefixProvider* dpp, const req_state* s) noexcept
{
  auto& argmap = s->info.args;
  auto maybe_expires = argmap.get_optional("Expires");
  if (!maybe_expires) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("{}: Missing Expires parameter"), __func__) << dendl;
    return std::nullopt;
  }

  auto expiry_time_str = std::move(*maybe_expires);
  time_t expiry_time;
  if (!absl::SimpleAtoi(expiry_time_str, &expiry_time)) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("Failed to parse int from Expires='{}'"), __func__, expiry_time_str) << dendl;
    return std::nullopt;
  }
  ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("{}: expiry time "), __func__, expiry_time) << dendl;
  return std::make_optional(expiry_time);
}

bool HandoffHelperImpl::valid_presigned_time(const DoutPrefixProvider* dpp, const req_state* s, time_t now)
{
  std::optional<time_t> maybe_expiry_time;

  auto& argmap = s->info.args;
  if (argmap.exists("AWSAccessKeyId")) {
    maybe_expiry_time = get_v2_presigned_expiry_time(dpp, s);
  } else if (argmap.exists("x-amz-credential")) {
    maybe_expiry_time = get_v4_presigned_expiry_time(dpp, s);
  }
  if (!maybe_expiry_time) {
    ldpp_dout(dpp, 0) << "Unable to extract presigned URL expiry time from query parameters" << dendl;
    return false;
  }
  ldpp_dout(dpp, 20) << fmt::format(FMT_STRING("Presigned URL last valid second {} now {}"), *maybe_expiry_time, now) << dendl;
  if (*maybe_expiry_time < now) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("Presigned URL expired - last valid second {} now {}"), *maybe_expiry_time, now) << dendl;
    return false;
  }
  return true;
}

/**
 * @brief For a given HTTP method in string form ("GET", "POST", etc.) return
 * the corresponding request HTTPMethod enum value.
 *
 * This is used to map the request type we get from RGW onto the enum the API
 * expects.
 *
 * @param method The HTTP method as a string view.
 * @return authenticator::v1::AuthenticateRESTRequest::HTTPMethod the enum
 * value, or ...HTTP_METHOD_UNSPECIFIED if the method is not recognised.
 */
static authenticator::v1::AuthenticateRESTRequest::HTTPMethod method_to_reqmethod(const std::string_view& method)
{
  if (method == "GET") {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_GET;
  } else if (method == "PUT") {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_PUT;
  } else if (method == "POST") {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_POST;
  } else if (method == "DELETE") {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_DELETE;
  } else if (method == "HEAD") {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_HEAD;
  } else {
    return AuthenticateRESTRequest_HTTPMethod_HTTP_METHOD_UNSPECIFIED;
  }
}

HandoffAuthResult HandoffHelperImpl::auth(const DoutPrefixProvider* dpp_in,
    const std::string_view& session_token,
    const std::string_view& access_key_id,
    const std::string_view& string_to_sign,
    const std::string_view& signature,
    const req_state* const s,
    optional_yield y)
{
  // Construct a custom log prefix provider with some per-request state
  // information. This should make it easier to correlate logs on busy
  // servers.
  auto hdpp = HandoffDoutStateProvider(*dpp_in, s);
  // All the APIs expect a *DoutPrefixProvider.
  auto dpp = &hdpp;

  ceph_assert(s->cio != nullptr); // Give a helpful message to unit tests.

  ldpp_dout(dpp, 1) << fmt::format(FMT_STRING(
                                       "init: access_key_id='{}' session_token_present={} decoded_uri='{}' domain={}"),
      access_key_id,
      session_token.empty() ? "false" : "true",
      s->decoded_uri,
      s->info.domain)
                    << dendl;

  // The 'environment' of the request includes, amongst other things,
  // all the headers, prefixed with 'HTTP_'. They also have header names
  // uppercased and with underscores instead of hyphens.
  auto envmap = s->cio->get_env().get_map();

  // Make sure runtime configuration is defined throughout this method.
  std::shared_lock<std::shared_mutex> g(m_config_);

  // Retrieve the Authorization header if present. Otherwise, attempt to
  // synthesize one from the provided query parameters.
  std::string auth;
  auto srch = envmap.find("HTTP_AUTHORIZATION");
  if (srch != envmap.end()) {
    auth = srch->second;
    ldpp_dout(dpp, 20) << "Authorization=" << auth << dendl;

  } else {
    // Attempt to create an Authorization header using query parameters.
    auto maybe_auth = synthesize_auth_header(dpp, s);
    if (maybe_auth) {
      auth = std::move(*maybe_auth);
      ldpp_dout(dpp, 20) << "Synthesized Authorization=" << auth << dendl;
    } else {
      ldpp_dout(dpp, 0) << "Missing Authorization header and insufficient query parameters" << dendl;
      return HandoffAuthResult(-EACCES, "Internal error (missing Authorization and insufficient query parameters)");
    }
    if (presigned_expiry_check_) {
      // Belt-and-braces: Check the expiry time. Note that RGW won't (in
      // v17.2.6) pass this to authenticate() (and so auth()); it checks the
      // expiry time early. Let's not assume things.
      if (!valid_presigned_time(dpp, s, time(nullptr))) {
        ldpp_dout(dpp, 0) << "Presigned URL expiry check failed" << dendl;
        return HandoffAuthResult(-EACCES, "Presigned URL expiry check failed");
      }
    }
  }

  // We might have disabled V2 signatures.
  if (!enable_signature_v2_) {
    if (ba::starts_with(auth, "AWS ")) {
      ldpp_dout(dpp, 0) << "V2 signatures are disabled, returning failure" << dendl;
      return HandoffAuthResult(-EACCES, "Access denied (V2 signatures disabled)");
    }
  }

  std::optional<AuthorizationParameters> authorization_param;

  // The user can control when we send authorization parameters. Making it
  // runtime configurable makes it trivial to eliminate this feature as a
  // cause of performance problems.
  //
  if (authorization_mode_ == AuthParamMode::ALWAYS || (authorization_mode_ == AuthParamMode::WITHTOKEN && !session_token.empty())) {
    authorization_param = AuthorizationParameters(dpp, s);
    // Log the result. It's safe to dereference the optional, as the constructor
    // always returns an object (though it may be invalid w.r.t. its valid()
    // method).
    ldpp_dout(dpp, 20) << *authorization_param << dendl;

    if (!(authorization_param->valid())) {
      // This shouldn't happen with a valid request. If it does, log it and
      // re-nullopt the authorization parameters.
      ldpp_dout(dpp, 0) << "AuthorizationParameters not available" << dendl;
      authorization_param = std::nullopt;
    }
  }

  // Determine if we're a chunked upload. The spec
  // (https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html)
  // says that we have to set the content-encoding: HTTP header, but the only
  // client I can find (minio go) doesn't set it. We won't depend on it.
  //
  bool is_chunked = false;

  auto aws_content = envmap.find("HTTP_X_AMZ_CONTENT_SHA256");
  if (aws_content != envmap.cend()) {
    if (aws_content->second == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
      is_chunked = true;
      ldpp_dout(dpp, 5) << "chunked upload in progress" << dendl;
    }
  }

  if (is_chunked && !enable_chunked_upload_) {
    ldpp_dout(dpp, 5) << "chunked upload disabled - rejecting request" << dendl;
    return HandoffAuthResult(-EACCES, "chunked upload is disabled");
  }

  // Perform the gRPC-specific parts of the auth* call.
  auto result = _grpc_auth(dpp, auth, authorization_param, session_token, access_key_id, string_to_sign, signature, s, y);

  if (result.is_err()) {
    return result;
  }
  // If we're chunked, we need a signing key from the Authenticator.
  if (!is_chunked) {
    return result;
  } else {
    auto sk = get_signing_key(dpp, auth, s, y);
    if (!sk.has_value()) {
      ldpp_dout(dpp, 0) << "failed to fetch signing key for chunked upload"
                        << dendl;
      return HandoffAuthResult(
          -EACCES, "failed to fetch signing key for chunked upload");
    }
    result.set_signing_key(*sk);
    ldpp_dout(dpp, 10) << "chunked upload signing key saved" << dendl;
    return result;
  }
};

HandoffAuthResult HandoffHelperImpl::_grpc_auth(const DoutPrefixProvider* dpp_in,
    const std::string& auth,
    const std::optional<AuthorizationParameters>& authorization_param,
    [[maybe_unused]] const std::string_view& session_token,
    const std::string_view& access_key_id,
    const std::string_view& string_to_sign,
    const std::string_view& signature,
    [[maybe_unused]] const req_state* const s,
    [[maybe_unused]] optional_yield y)
{
  auto hdpp = HandoffDoutPrefixPipe(*dpp_in, "grpc_auth");
  auto dpp = &hdpp;

  authenticator::v1::AuthenticateRESTRequest req;
  // Fill in the request protobuf. Seem to have to create strings from
  // string_view, which is a shame.
  req.set_transaction_id(s->trans_id);
  req.set_string_to_sign(std::string { string_to_sign });
  req.set_authorization_header(auth);

  // If we got authorization parameters, fill them in.
  if (authorization_param) {
    req.set_http_method(method_to_reqmethod(authorization_param->method()));
    if (!authorization_param->bucket_name().empty()) {
      req.set_bucket_name(authorization_param->bucket_name());
    }
    if (!authorization_param->object_key_name().empty()) {
      req.set_object_key(authorization_param->object_key_name());
    }

    const auto headers = authorization_param->http_headers();
    if (headers.size() > 0) {
      auto req_headers = req.mutable_x_amz_headers();
      for (const auto& kv : headers) {
        req_headers->insert({ kv.first, kv.second });
      }
    }

    const auto query_params = authorization_param->http_query_params();
    if (query_params.size() > 0) {
      auto req_query_params = req.mutable_query_parameters();
      for (const auto& kv : query_params) {
        req_query_params->insert({ kv.first, kv.second });
      }
    }
  }

  // Get the gRPC client from under the channel lock. Hold the lock for as
  // short a time as possible.
  AuthServiceClient client {}; // Uninitialised variant - must call set_stub().
  {
    std::shared_lock<std::shared_mutex> g(m_channel_);
    // Quick confidence check of channel_.
    if (!channel_) {
      ldpp_dout(dpp, 0) << "Unset gRPC channel" << dendl;
      return HandoffAuthResult(-EACCES, "Internal error (gRPC channel not set)");
    }
    client.set_stub(channel_);
  }
  ldpp_dout(dpp, 1) << "Sending gRPC auth request" << dendl;
  auto result = client.Auth(req);

  // The client returns a fully-populated HandoffAuthResult, but we want to
  // issue some helpful log messages before returning it.
  if (result.is_ok()) {
    ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("success (access_key_id='{}', uid='{}')"), access_key_id, result.userid()) << dendl;
  } else {
    if (result.err_type() == HandoffAuthResult::error_type::TRANSPORT_ERROR) {
      ldpp_dout(dpp, 0) << fmt::format(FMT_STRING("authentication attempt failed: {}"), result.message()) << dendl;
    } else {
      ldpp_dout(dpp, 0) << fmt::format(
          FMT_STRING("Authentication service returned failure (access_key_id='{}', code={}, message='{}')"),
          access_key_id, result.code(), result.message())
                        << dendl;
    }
  }

  return result;
}

std::optional<std::vector<uint8_t>>
HandoffHelperImpl::get_signing_key(const DoutPrefixProvider* dpp,
    const std::string auth,
    const req_state* const s, optional_yield y)
{

  authenticator::v1::GetSigningKeyRequest req;
  req.set_transaction_id(s->trans_id);
  req.set_authorization_header(auth);

  // Get the gRPC client from under the channel lock. Hold the lock for as
  // short a time as possible.
  AuthServiceClient client {}; // Uninitialised variant - must call set_stub().
  {
    std::shared_lock<std::shared_mutex> g(m_channel_);
    // Quick confidence check of channel_.
    if (!channel_) {
      ldpp_dout(dpp, 0) << "Unset gRPC channel" << dendl;
      return std::nullopt;
    }
    client.set_stub(channel_);
  }
  ldpp_dout(dpp, 1) << "Sending gRPC signing key request" << dendl;
  auto result = client.GetSigningKey(req);
  if (!result.ok()) {
    ldpp_dout(dpp, 1) << "Failed to fetch signing key: " << result.error_message() << dendl;
    return std::nullopt;
  }
  ldpp_dout(dpp, 5) << "fetched signing key" << dendl;
  return std::make_optional(result.signing_key());
}

} // namespace rgw
