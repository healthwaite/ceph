/**
 * @file rgw_handoff_impl.h
 * @author André Lucas (alucas@akamai.com)
 * @brief Handoff declarations involving gRPC.
 * @version 0.1
 * @date 2023-11-10
 *
 * @copyright Copyright (c) 2023
 *
 * Declarations for HandoffHelperImpl and related classes.
 *
 * TRY REALLY HARD to not include this anywhere except handoff.cc and
 * handoff_impl.cc. In particular, don't add it to rgw_handoff.h no matter how
 * tempting that seems.
 *
 * This file pulls in the gRPC headers and we don't want that everywhere.
 */

#ifndef RGW_HANDOFF_IMPL_H
#define RGW_HANDOFF_IMPL_H

#include <functional>
#include <iosfwd>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <fmt/format.h>
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/server_credentials.h>

#include "common/async/yield_context.h"
#include "common/config_obs.h"
#include "common/dout.h"
#include "rgw/rgw_common.h"

#include "authenticator/v1/authenticator.grpc.pb.h"
#include "authenticator/v1/authenticator.pb.h"
using namespace ::authenticator::v1;

#include "rgw_handoff.h"

namespace rgw {

/****************************************************************************/

/**
 * @brief Implement DoutPrefixPipe for a simple prefix string.
 *
 * To add an additional string (which will be followed by ": ") to the
 * existing log prefix, use:
 *
 * ```
 * auto hdpp = HandoffDoutPrefixPipe(*dpp_in, foo);
 * auto dpp = &hdpp;
 * ```
 *
 * It will save time to create a DoutPrefixProvider*, as demonstrated by the
 * unit tests it's quite jarring to have to use &dpp.
 */
class HandoffDoutPrefixPipe : public DoutPrefixPipe {
  const std::string prefix_;

public:
  HandoffDoutPrefixPipe(const DoutPrefixProvider& dpp, const std::string& prefix)
      : DoutPrefixPipe { dpp }
      , prefix_ { fmt::format(FMT_STRING("{}: "), prefix) }
  {
  }
  virtual void add_prefix(std::ostream& out) const override final
  {
    out << prefix_;
  }
};

/**
 * @brief Add request state as a prefix to the log message. This should be
 * used to help support engineers correlate log messages.
 *
 * Pass in the request state.
 *
 * ```
 * auto hdpp = HandoffDoutStateProvider(*dpp_in, s);
 * auto dpp = &hdpp;
 * ```
 */
class HandoffDoutStateProvider : public HandoffDoutPrefixPipe {

public:
  /**
   * @brief Construct a new Handoff Dout Pipe Provider object with an existing
   * provider and the request state.
   *
   * Use our HandoffDoutPrefixPipe implementation for implementation.
   *
   * @param dpp An existing DoutPrefixProvider reference.
   * @param s The request state.
   */
  HandoffDoutStateProvider(const DoutPrefixProvider& dpp, const req_state* s)
      : HandoffDoutPrefixPipe {
        dpp, fmt::format(FMT_STRING("HandoffEngine trans_id={}"), s->trans_id)
      } {};
};

/****************************************************************************/

/**
 * @brief The result of parsing the HTTP response from the Authenticator service.
 *
 * Used by the HTTP arm of auth() to encapsulate the various possible results
 * from parsing the Authenticator's JSON.
 */
class HandoffHTTPVerifyResult {
  int result_;
  long http_code_;
  std::string query_url_;

public:
  HandoffHTTPVerifyResult()
      : result_ { -1 }
      , http_code_ { 0 }
      , query_url_ { "" }
  {
  }
  HandoffHTTPVerifyResult(int result, long http_code, std::string query_url = "")
      : result_ { result }
      , http_code_ { http_code }
      , query_url_ { query_url }
  {
  }
  // No copy or copy-assignment.
  HandoffHTTPVerifyResult(const HandoffHTTPVerifyResult& other) = delete;
  HandoffHTTPVerifyResult& operator=(const HandoffHTTPVerifyResult& other) = delete;
  // Trivial move and move-assignment.
  HandoffHTTPVerifyResult(HandoffHTTPVerifyResult&& other) = default;
  HandoffHTTPVerifyResult& operator=(HandoffHTTPVerifyResult&& other) = default;

  int result() const noexcept { return result_; }
  long http_code() const noexcept { return http_code_; }
  std::string query_url() const noexcept { return query_url_; }
};

/****************************************************************************/

/**
 * @brief gRPC client wrapper for rgw/auth/v1/AuthService.
 *
 * Very thin wrapper around the gRPC client. Construct with a channel to
 * create a stub. Call services via the corresponding methods, with sanitised
 * return values.
 */
class AuthServiceClient {
private:
  std::unique_ptr<AuthenticatorService::Stub> stub_;

public:
  /**
   * @brief Return value from GetSigningKey().
   */
  class GetSigningKeyResult {
    std::vector<uint8_t> signing_key_;
    bool success_;
    std::string error_message_;

  public:
    /**
     * @brief Construct a success-type result.
     *
     * @param key The signing key.
     */
    GetSigningKeyResult(std::vector<uint8_t> key)
        : signing_key_ { key }
        , success_ { true }
    {
    }

    /**
     * @brief Construct a failure-type result.
     *
     * ok() will return false.
     *
     * @param msg A human-readable error message.
     */
    GetSigningKeyResult(std::string msg)
        : success_ { false }
        , error_message_ { msg }
    {
    }

    // Can't have a copy constructor with a unique_ptr.
    GetSigningKeyResult(const GetSigningKeyResult&) = delete;
    GetSigningKeyResult& operator=(const GetSigningKeyResult&) = delete;
    // Move is fine.
    GetSigningKeyResult(GetSigningKeyResult&&) = default;
    GetSigningKeyResult& operator=(GetSigningKeyResult&&) = default;

    /// @brief Return true if a signing key is present, false otherwise.
    bool ok() const noexcept { return success_; }
    /// Return true if this is a failure-type object, false otherwise.
    bool err() const noexcept { return !ok(); }

    /**
     * @brief Return the signing key if present, otherwise throw std::runtime_error.
     *
     * @return std::vector<uint8_t> The signing key.
     * @throws std::runtime_error if this is a failure-type object.
     */
    std::vector<uint8_t> signing_key() const
    {
      if (!ok()) {
        throw std::runtime_error("signing_key() called in error");
      }
      return signing_key_;
    }
    /**
     * @brief Return an error message if present, otherwise an empty string.
     *
     * @return std::string The error message. May be empty.
     */
    std::string error_message() const noexcept { return error_message_; }
  }; // class AuthServiceClient::GetSigningKeyResult

  /**
   * @brief Construct a new Auth Service Client object. You must use set_stub
   * before using any gRPC calls, or the object's behaviour is undefined.
   */
  AuthServiceClient() { }

  /**
   * @brief Construct a new AuthServiceClient object and initialise the gRPC
   * stub.
   *
   * @param channel pointer to the grpc::Channel object to be used.
   */
  explicit AuthServiceClient(std::shared_ptr<::grpc::Channel> channel)
      : stub_(AuthenticatorService::NewStub(channel))
  {
  }

  // Copy constructors can't work with the stub unique_ptr.
  AuthServiceClient(const AuthServiceClient&) = delete;
  AuthServiceClient& operator=(const AuthServiceClient&) = delete;
  // Moves are fine.
  AuthServiceClient(AuthServiceClient&&) = default;
  AuthServiceClient& operator=(AuthServiceClient&&) = default;

  /**
   * @brief Set the gRPC stub for this object.
   *
   * @param channel the gRPC channel pointer.
   */
  void set_stub(std::shared_ptr<::grpc::Channel> channel)
  {
    stub_ = AuthenticatorService::NewStub(channel);
  }

  /**
   * @brief Call rgw::auth::v1::AuthService::Auth() and return a
   * HandoffAuthResult, suitable for HandoffHelperImpl::auth().
   *
   * On success, return the embedded username. We don't currently support the
   * original_user_id field of the response message, as we have no current use
   * for it.
   *
   * On error, parse the result for an S3ErrorDetails message embedded in the
   * details field. (Richer error model.) If we find one, return the error
   * message and embed the contained HTTP status code. It's up to the caller
   * to follow up and pass the HTTP status code back to RGW in the proper
   * form, it won't do to return the raw HTTP status code! We're assuming the
   * Authenticator knows what HTTP code it wants returned, and it's up to
   * Handoff to interpret it properly and return a useful code.
   *
   * If we don't find an S3ErrorDetails message, return a generic error (with
   * the provided error message) with error type TRANSPORT_ERROR. This allows
   * the caller to differentiate between authentication problems and RPC
   * problems.
   *
   * The alternative to using HandoffAuthResult would be interpreting the
   * request status and result object would be either returning a bunch of
   * connection status plus an AuthResponse object, or throwing exceptions on
   * error. This feels like an easier API to use in our specific use case.
   *
   * @param req the filled-in authentication request protobuf
   * (rgw::auth::v1::AuthRequest).
   * @return HandoffAuthResult A completed auth result.
   */
  HandoffAuthResult Auth(const AuthenticateRESTRequest& req);

  /**
   * @brief Map an Authenticator gRPC error code onto an error code that RGW
   * can digest.
   *
   * The Authenticator returns a details error code in S3ErrorDetails.Type. We
   * need to map this onto the list of error codes in rgw_common.cc, array
   * rgw_http_s3_errors. There may be exceptions if the inbuild RGW codes that
   * match the Authenticator codes don't return the proper HTTP status code.
   * This will probably need tweaked over time.
   *
   * If there's no direct mapping, we'll try to map a subset of HTTP error
   * codes onto a matching RGW error code. If we can't do that, we'll return
   * EACCES which results in an HTTP 403.
   *
   * @param auth_type The Authenticator error code (S3ErrorDetails.Type).
   * @param auth_http_status_code The desired HTTP status code.
   * @param message The Authenticator's error message (copied verbatim into
   * the HandoffAuthResult).
   * @return HandoffAuthResult
   */
  static HandoffAuthResult _translate_authenticator_error_code(
      ::authenticator::v1::S3ErrorDetails_Type auth_type,
      int32_t auth_http_status_code,
      const std::string& message);

  /**
   * @brief Request a signing key for the given authorization header. The
   * signing key is valid on the day it is issued, as it has a date component
   * in the HMAC.
   *
   * This is intended for use with chunked uploads, but may be useful for
   * caching purposes as the singing key allows us to authenticate locally.
   * However, it would also reduce the granularity of credential changes so I
   * don't recommend it be used with a time window of a day. Maybe 15 minutes
   * is acceptable, though honestly if we were to use this in anger I would
   * recommend an API to imperatively expire credentials.
   *
   * @param req A properly filled authenticator.v1.GetSigningKeyRequest
   * protobuf message.
   * @return A GetSigningKeyResult object.
   */
  GetSigningKeyResult GetSigningKey(const GetSigningKeyRequest req);
};

/****************************************************************************/

/**
 * @brief Gathered information about an inflight request that we want to sent
 * to the Authentication service for verification.
 *
 * Normally these data are gathered later in the request and subject to
 * internal policies, acls etc. We're giving the Authentication service a
 * chance to see this information early.
 */
class AuthorizationParameters {

private:
  bool valid_;
  std::string method_;
  std::string bucket_name_;
  std::string object_key_name_;
  std::unordered_map<std::string, std::string> http_headers_;
  std::string http_request_path_;
  std::unordered_map<std::string, std::string> http_query_params_;

  void valid_check() const
  {
    if (!valid()) {
      throw new std::runtime_error("AuthorizationParameters not valid");
    }
  }

public:
  AuthorizationParameters(const DoutPrefixProvider* dpp, const req_state* s) noexcept;

  // Standard copies and moves are fine.
  AuthorizationParameters(const AuthorizationParameters& other) = default;
  AuthorizationParameters& operator=(const AuthorizationParameters& other) = default;
  AuthorizationParameters(AuthorizationParameters&& other) = default;
  AuthorizationParameters& operator=(AuthorizationParameters&& other) = default;

  /**
   * @brief Return the validity of this AuthorizationParameters object.
   *
   * If at construction time the request was well-formed and contained
   * sufficient information to be used in an authorization request to the
   * Authenticator, return true.
   *
   * Otherwise, return false.
   *
   * @return true The request can be used as the source of an
   * authorization-enhanced authentication operation.
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
   * @brief Convert this AuthorizationParameters object to string form.
   *
   * Note we don't dump the object key name - this might be a large string,
   * might be full of invalid characters, or might be private.
   *
   * @return std::string A string representation of the object. Works fine for
   * objects in the invalid state; this call is always safe.
   */
  std::string to_string() const noexcept;

  /**
   * @brief Return a const reference to the map of HTTP headers.
   *
   * @return const std::unordered_map<std::string, std::string>& A read-only
   * reference to the HTTP headers map.
   */
  const std::unordered_map<std::string, std::string>& http_headers() const
  {
    valid_check();
    return http_headers_;
  }

  /**
   * @brief Return the http request path (req_info.request_uri).
   *
   * @return std::string the request path.
   */
  std::string http_request_path() const
  {
    valid_check();
    return http_request_path_;
  }

  /**
   * @brief Return a const reference to the map of HTTP query parameters.
   *
   * @return const std::unordered_map<std::string, std::string>& A read-only
   * reference to the HTTP query parameters map.
   */
  const std::unordered_map<std::string, std::string>& http_query_params() const
  {
    valid_check();
    return http_query_params_;
  }

  friend std::ostream& operator<<(std::ostream& os, const AuthorizationParameters& ep);

}; // class AuthorizationParameters.

std::ostream& operator<<(std::ostream& os, const AuthorizationParameters& ep);

/****************************************************************************/

enum class AuthParamMode {
  NEVER,
  WITHTOKEN,
  ALWAYS
};

/**
 * @brief Config Observer utility class for HandoffHelperImpl.
 *
 * This is constructed so as to make it feasible to mock the ConfigObserver
 * interface. We can construct an instance of this class with a mocked helper,
 * just so long as that mocked helper implements the proper signature. There's
 * no way to formally specify the required signatures in advance in C++,
 * compile-time polymorphism means running the SFINAE gauntlet.
 *
 * As of 20231127, T must implement (with the same signature as
 * HandoffHelperImpl):
 *   - get_default_channel_args()
 *   - set_channel_args()
 *   - set_channel_uri()
 *   - set_signature_v2()
 *   - set_authorization_mode()
 *   - set_chunked_upload_mode()
 *
 * or it won't compile.
 *
 * @tparam T The HandoffHelperImpl-like class. The class has to implement the
 * same configuration mutation methods as HandoffHelperImpl.
 */
template <typename T>
class HandoffConfigObserver final : public md_config_obs_t {
public:
  /**
   * @brief Construct a new Handoff Config Observer object with a
   * backreference to the owning HandoffHelperImpl.
   *
   * @param helper
   */
  explicit HandoffConfigObserver(T& helper)
      : helper_(helper)
  {
  }

  // Don't allow a default construction without the helper_.
  HandoffConfigObserver() = delete;

  /**
   * @brief Destructor. Remove the observer from the Ceph configuration system.
   *
   */
  ~HandoffConfigObserver()
  {
    if (cct_ && observer_added_) {
      cct_->_conf.remove_observer(this);
    }
  }

  void init(CephContext* cct)
  {
    cct_ = cct;
    cct_->_conf.add_observer(this);
    observer_added_ = true;
  }

  /**
   * @brief Read config and return the resultant AuthParamMode in effect.
   *
   * @param conf ConfigProxy reference.
   * @return AuthParamMode the mode in effect based on system config.
   */
  AuthParamMode get_authorization_mode(const ConfigProxy& conf) const
  {
    if (conf->rgw_handoff_authparam_always) {
      return AuthParamMode::ALWAYS;
    } else if (conf->rgw_handoff_authparam_withtoken) {
      return AuthParamMode::WITHTOKEN;
    } else {
      return AuthParamMode::NEVER;
    }
  }

  // Config observer. See notes in src/common/config_obs.h and for
  // ceph::md_config_obs_impl.

  const char** get_tracked_conf_keys() const
  {
    static const char* keys[] = {
      "rgw_handoff_authparam_always",
      "rgw_handoff_authparam_withtoken",
      "rgw_handoff_enable_chunked_upload",
      "rgw_handoff_enable_signature_v2",
      "rgw_handoff_grpc_arg_initial_reconnect_backoff_ms",
      "rgw_handoff_grpc_arg_max_reconnect_backoff_ms",
      "rgw_handoff_grpc_arg_min_reconnect_backoff_ms",
      "rgw_handoff_grpc_uri",
      nullptr
    };
    return keys;
  }

  void handle_conf_change(const ConfigProxy& conf,
      const std::set<std::string>& changed)
  {
    // You should bundle any gRPC arguments changes into this first block.
    if (changed.count("rgw_handoff_grpc_arg_initial_reconnect_backoff_ms") || changed.count("rgw_handoff_grpc_arg_max_reconnect_backoff_ms") || changed.count("rgw_handoff_grpc_arg_min_reconnect_backoff_ms")) {
      auto args = helper_.get_default_channel_args(cct_);
      helper_.set_channel_args(cct_, args);
    }
    // The gRPC channel change needs to come after the arguments setting, if any.
    if (changed.count("rgw_handoff_grpc_uri")) {
      helper_.set_channel_uri(cct_, conf->rgw_handoff_grpc_uri);
    }
    if (changed.count("rgw_handoff_enable_chunked_upload")) {
      helper_.set_chunked_upload_mode(cct_, conf->rgw_handoff_enable_chunked_upload);
    }
    if (changed.count("rgw_handoff_enable_signature_v2")) {
      helper_.set_signature_v2(cct_, conf->rgw_handoff_enable_signature_v2);
    }
    if (changed.count("rgw_handoff_authparam_always") || changed.count("rgw_handoff_authparam_withtoken")) {
      helper_.set_authorization_mode(cct_, get_authorization_mode(conf));
    }
  }

private:
  T& helper_;
  CephContext* cct_ = nullptr;
  bool observer_added_ = false;
};

/****************************************************************************/

/**
 * @brief Support class for 'handoff' authentication.
 *
 * Used by rgw::auth::s3::HandoffEngine to implement authentication via an
 * external Authenticator Service.
 *
 * In gRPC mode, holds long-lived state.
 */
class HandoffHelperImpl final {

public:
  // Signature of the alternative verify function,  used only for testing.
  using HTTPVerifyFunc = std::function<HandoffHTTPVerifyResult(const DoutPrefixProvider*, const std::string&, ceph::bufferlist*, optional_yield)>;
  using chan_lock_t = std::shared_mutex;

private:
  // Ceph configuration observer.
  HandoffConfigObserver<HandoffHelperImpl> config_obs_;

  // This is a test helper for the HTTP mode only.
  const std::optional<HTTPVerifyFunc> http_verify_func_;

  // The store should be constant throughout the lifetime of the helper.
  rgw::sal::Driver* store_;

  // These are used in place of constantly querying the ConfigProxy.
  std::shared_mutex m_config_;
  bool grpc_mode_ = true; // Not runtime-alterable.
  bool presigned_expiry_check_ = false; // Not runtime-alterable.
  bool enable_signature_v2_ = true; // Runtime-alterable.
  bool enable_chunked_upload_ = true; // Runtime-alterable.
  AuthParamMode authorization_mode_ = AuthParamMode::ALWAYS; // Runtime-alterable.

  // The gRPC channel pointer needs to be behind a mutex. Changing channel_,
  // channel_args_ or channel_uri_ must be under a unique lock of m_channel_.
  std::shared_mutex m_channel_;
  std::shared_ptr<grpc::Channel> channel_;
  std::optional<grpc::ChannelArguments> channel_args_;
  std::string channel_uri_;

public:
  /**
   * @brief Construct a new HandoffHelperImpl object.
   *
   * This is the constructor to use for all except unit tests. Note no
   * persisted state is set up; that's done by calling init().
   */
  HandoffHelperImpl()
      : config_obs_(*this)
  {
  }

  ~HandoffHelperImpl() = default;

  /**
   * @brief Construct a new Handoff Helper object with an alternative callout
   * mechanism. Used by test harnesses.
   *
   * @param v A function to replace the HTTP client callout. This must mimic
   * the inputs and outputs of the \p http_verify_standard() function.
   */
  HandoffHelperImpl(HTTPVerifyFunc v)
      : config_obs_ { *this }
      , http_verify_func_ { v }
  {
  }

  /**
   * @brief Initialise any long-lived state for this engine.
   * @param cct Pointer to the Ceph context.
   * @param store Pointer to the sal::Store object.
   * @param grpc_uri Optional URI for the gRPC server. If empty (the default),
   * config value rgw_handoff_grpc_uri is used.
   * @return 0 on success, otherwise failure.
   *
   * Store long-lived state.
   *
   * The \p store pointer isn't used at this time.
   *
   * In gRPC mode, a grpc::Channel is created and stored on the object for
   * later use. This will manage the persistent connection(s) for all gRPC
   * communications.
   */
  int init(CephContext* const cct, rgw::sal::Driver* store, const std::string& grpc_uri = "");

  /**
   * @brief Set the gRPC channel URI.
   *
   * This is used by init() and by the config observer. If no channel
   * arguments have been set via set_channel_args(), this will set them to the
   * default values (via get_default_channel_args).
   *
   * Do not call from auth() unless you _know_ you've not taken a lock on
   * m_config_!
   *
   * @param grpc_uri
   * @return true on success.
   * @return false on failure.
   */
  bool set_channel_uri(CephContext* const cct, const std::string& grpc_uri);

  /**
   * @brief Configure support for AWS signature v2.
   *
   * I strongly recommend this remain enabled for broad client support.
   *
   * Do not call from auth() unless you _know_ you've not taken a lock on
   * m_config_!
   *
   * @param enabled Whether or not V2 signatures should be allowed.
   */
  void set_signature_v2(CephContext* const cct, bool enabled);

  /**
   * @brief Set the authorization mode for subsequent requests.
   *
   * Do not call from auth() unless you _know_ you've not taken a lock on
   * m_config_!
   *
   * @param cct CephContext pointer.
   * @param mode The authorization mode.
   */
  void set_authorization_mode(CephContext* const cct, AuthParamMode mode);

  /**
   * @brief Configure chunked upload mode.
   *
   * This should probably remain enabled, but the toggle exists just in case
   * we have performance problems with the additional gRPC calls this
   * requires.
   *
   * @param cct CephContext pointer.
   * @param enabled Whether or not chunked uploads should be allowed.
   */
  void set_chunked_upload_mode(CephContext* const cct, bool enabled);

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
   * auth() runs with shared lock of m_config_, so runtime-alterable
   * configuration isn't undefined during a single authentication.
   * Modifications to the affected runtime parameters are performed under a
   * unique lock of m_config_.
   *
   * - Extract the Authorization header from the environment. This will be
   *   necessary to validate a v4 signature because we need some fields (date,
   *   region, service, request type) for step 2 of the signature process.
   *
   * - If the Authorization header is absent, attempt to extract the relevant
   *   information from query parameters to synthesize an Authorization
   *   header. This is to support presigned URLs.
   *
   * - If the header indicates AWS Signature V2 authentication, but V2 is
   *   disabled via configuration, return a failure immediately.
   *
   * - If required, introspect the request to obtain additional authentication
   *   parameters that might be required by the external authenticator.
   *
   * - Depending on configuration, call either the gRPC arm (_grpc_auth()) or
   *   the HTTP arm (_http_auth()) and return the result.
   *
   */
  HandoffAuthResult auth(const DoutPrefixProvider* dpp,
      const std::string_view& session_token,
      const std::string_view& access_key_id,
      const std::string_view& string_to_sign,
      const std::string_view& signature,
      const req_state* const s,
      optional_yield y);

  /**
   * @brief Implement the gRPC arm of auth().
   *
   * @param dpp DoutPrefixProvider.
   * @param auth The authorization header, which may have been synthesized.
   * @param authorization_param Authorization parameters, if required.
   * @param session_token Unused by Handoff.
   * @param access_key_id The S3 access key.
   * @param string_to_sign The canonicalised S3 signature input.
   * @param signature The transaction signature provided by the user.
   * @param s Pointer to the req_state.
   * @param y An optional yield token.
   * @return HandoffAuthResult The authentication result.
   *
   * Implement a Handoff authentication request using gRPC.
   *
   * - Fill in the provided information in the request protobuf
   *   (rgw::auth::v1::AuthRequest).
   *
   * - If authorization parameters are provided, fill those in in the protobuf
   *   as well.
   *
   * - Send the request using an instance of rgw::AuthServiceClient. note that
   *   AuthServiceClient::Auth() handles the translation of the response code
   *   into a code suitable to be returned to RGW as the result of the engine
   *   authenticate() call.
   *
   * - If the gRPC request itself failed, log the error and return 'access
   *   denied'.
   *
   * - Log the authentication request's success or failure, and return the
   *   result from AuthServiceClient::Auth().
   */
  HandoffAuthResult _grpc_auth(const DoutPrefixProvider* dpp,
      const std::string& auth,
      const std::optional<AuthorizationParameters>& authorization_param,
      const std::string_view& session_token,
      const std::string_view& access_key_id,
      const std::string_view& string_to_sign,
      const std::string_view& signature,
      const req_state* const s,
      optional_yield y);

  /**
   * @brief Attempt to retrieve a signing key from the Authenticator.
   *
   * Request the signing key from the Authenticator. The signing key has a
   * validity of one day, so must be cached only with careful consideration.
   * We definitely should not cache it for a whole day.
   *
   * This can fail for a few reasons. The RPC can fail, or the Authenticator
   * may choose not to honour the request. We send the Authorization: header
   * and the internal transaction ID to try to help the Authenticator make a
   * decision.
   *
   * @param dpp The DoutPrefixProvider
   * @param auth The HTTP Authorization: header. Will be send verbatim to the
   * Authenticator.
   * @param s The request.
   * @param y The otional yield context.
   * @return std::optional<std::vector<uint8_t>> The signing key, or nullopt
   * on failure.
   */
  std::optional<std::vector<uint8_t>>
  get_signing_key(const DoutPrefixProvider *dpp, const std::string auth,
                  const req_state *const s, optional_yield y);

  /**
   * @brief Get our default grpc::ChannelArguments value.
   *
   * When calling set_channel_args(), you should first call this function to
   * get application defaults, and then modify the settings you need.
   *
   * Currently the backoff timers are set here, based on configuration
   * variables. These are runtime-alterable, but have sensible defaults.
   *
   * @return grpc::ChannelArguments A default set of channel arguments.
   */
  grpc::ChannelArguments get_default_channel_args(CephContext* const cct);

  /**
   * @brief Set custom gRPC channel arguments. Intended for testing.
   *
   * You should modify the default channel arguments obtained with
   * get_default_channel_args(). Don't start from scratch.
   *
   * Keep this simple. If you set vtable args you'll need to worry about the
   * lifetime of those is longer than the HandoffHelperImpl object that will
   * store a copy of the ChannelArguments object.
   *
   * Do not call from auth() unless you _know_ you've not taken a lock on
   * m_config_!
   *
   * @param args A populated grpc::ChannelArguments object.
   */
  void set_channel_args(CephContext* const cct, grpc::ChannelArguments& args)
  {
    std::unique_lock l { m_channel_ };
    channel_args_ = std::make_optional(args);
  }

  /**
   * @brief Implement the HTTP arm of auth().
   *
   * Implement a Handoff authentication request using REST.
   *
   * - Construct a JSON payload for the authenticator in the
   *   prescribed format.
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
   *
   * @param dpp DoutPrefixProvider.
   * @param auth The authorization header, which may have been synthesized.
   * @param authorization_param Authorization parameters, if required.
   * @param session_token Unused by Handoff.
   * @param access_key_id The S3 access key.
   * @param string_to_sign The canonicalised S3 signature input.
   * @param signature The transaction signature provided by the user.
   * @param s Pointer to the req_state.
   * @param y An optional yield token.
   * @return HandoffAuthResult The authentication result.
   */
  HandoffAuthResult _http_auth(const DoutPrefixProvider* dpp,
      const std::string& auth,
      const std::optional<AuthorizationParameters>& authorization_param,
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

}; // class HandoffHelperImpl

} /* namespace rgw */

#endif // RGW_HANDOFF_IMPL_H
