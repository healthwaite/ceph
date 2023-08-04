// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#pragma once

#include "rgw_op.h"
#include "rgw_rest_s3.h"

/**
 * @brief The type of S3 request for which the StoreQuery handler was invoked.
 *
 * Declare rather than infer the mode from which the handler is called.
 * Certain commands only make sense from certain modes - there's no point
 * querying an object if we're invoked by the RGWHandler_REST_Service_S3 - we
 * don't have enough information to query an object.
 */
enum class RGWSQHandlerType {
  Service,
  Bucket,
  Obj
};

/**
 * @brief Handler for StoreQuery REST commands (we only support S3).
 *
 * This handler requires the presence of the HTTP header x-rgw-storequery,
 * with specifically-formatted contents.
 *
 * XXX more.
 */
class RGWHandler_REST_StoreQuery_S3 : public RGWHandler_REST_S3 {
private:
  const RGWSQHandlerType handler_type_;

protected:
  int init_permissions(RGWOp* op, optional_yield y) override { return 0; }
  int read_permissions(RGWOp* op, optional_yield y) override { return 0; }
  bool supports_quota() override { return false; }

  /**
   * @brief Determine if a StoreQuery GET operation is being requested.
   *
   * If the x-rgw-storequery HTTP header is absent, return nullptr.
   *
   * If the x- header is present but its contents fail to pass, throw
   * -ERR_INTERNAL_ERROR to stop further processing of the request.
   *
   * Otherwise return an object of the appropriate RGWOp subclass to handle
   * the request.
   *
   * @return RGWOp* nullptr if no SQ GET operation, otherwise an RGWOp object
   * to process the operation.
   * @throws -ERR_INTERNAL_ERROR if the x-header is present, but the contents
   * fail to properly parse.
   */
  RGWOp* op_get() override;

  /**
   * @brief No-op - we don't handle PUT requests yet.
   *
   * @return RGWOp* nullptr.
   */
  RGWOp* op_put() override;

  /**
   * @brief No-op - we don't handle DELETE requests yet.
   *
   * @return RGWOp* nullptr.
   */
  RGWOp* op_delete() override;

public:
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  RGWHandler_REST_StoreQuery_S3(const rgw::auth::StrategyRegistry& auth_registry, RGWSQHandlerType handler_type)
      : RGWHandler_REST_S3(auth_registry),
        handler_type_{handler_type}
  {
  }
  virtual ~RGWHandler_REST_StoreQuery_S3() = default;
};

/// The longest supported value for the x-rgw-storequery header.
static constexpr size_t RGWSQMaxHeaderLength = 2048;

/**
 * @brief Parser for the x-rgw-storequery HTTP header.
 *
 * We need to parse the header and return an RGWOp-derived object to process
 * the REST operation associated with this request.
 *
 * XXX document header format.
 */
class RGWSQHeaderParser {
private:
  std::string command_;
  std::vector<std::string> param_;
  RGWOp* op_;

public:
  RGWSQHeaderParser() { }
  /// Reset the parser object.
  void reset();
  /// Tokenise the header value. Intended for testing, called implicitly by
  /// parse().
  bool tokenize(const DoutPrefixProvider* dpp, const std::string& input);
  /**
   * @brief Parse the value of the x-rgw-storequery header and configure this
   * to return an appropriate RGWOp* object.
   *
   * @param dpp prefix provider.
   * @param input The value of the X- header.
   * @param handler_type An enum showing what type of handler that called us.
   * This affects which types of commands are valid for a given request.
   * @return true The header was successfully parsed; op() will return a
   * useful object.
   * @return false The header was not parsed, and op() will return nullptr.
   */
  bool parse(const DoutPrefixProvider* dpp, const std::string& input, RGWSQHandlerType handler_type);
  RGWOp* op() { return op_; }
  std::string command() { return command_; }
  std::vector<std::string> param() { return param_; }
};

class RGWStoreQueryOp_Base : public RGWOp {
public:

  /**
   * @brief Bypass requester authorization checks for storequery commands.
   *
   * @param auth_registry The registry (ignored).
   * @param y optional yield.
   * @return int zero (success).
   */
  int verify_requester([[maybe_unused]] const rgw::auth::StrategyRegistry& auth_registry, [[maybe_unused]] optional_yield y) override { return 0; }
  /**
   * @brief Bypass permission checks for storequery commands.
   *
   * @param y optional yield.
   * @return int zero (success).
   */
  int verify_permission(optional_yield y) override { return 0; }
  uint32_t op_mask() override { return RGW_OP_TYPE_READ; }

  // `void execute(optional_yield_ y)` still required.
  // `void send_response()` still required;
  // `const char* name() const` still required.
};

/**
 * @brief StoreQuery ping command implementation.
 *
 * Return a copy of the user's request_id (in the header) without further
 * processing. Used to check the command path.
 *
 * ```
 * Query: (any path)
 * With header:
 *   x-rgw-storequery: ping foo
 *
 * Response: 200 OK
 * With body:
 *   <?xml
 * ```
 * XXX complete!
 */
class RGWStoreQueryOp_Ping : public RGWStoreQueryOp_Base {
private:
  std::string request_id_;

public:
  RGWStoreQueryOp_Ping(const std::string& _request_id)
      : request_id_ { _request_id }
  {
  }

  void execute(optional_yield y) override;
  void send_response() override;
  const char* name() const override { return "storequery_ping"; }
};

/**
 * @brief StoreQuery ObjectStatus command implementation.
 *
 * Return the status (presence, optionally other details) of an object in the
 * context of the existing query.
 *
 */
class RGWStoreQueryOp_ObjectStatus : public RGWStoreQueryOp_Base {
  std::string bucket_name_;
  std::string object_key_name_;
  std::string version_id_;
  size_t object_size_;

public:

  void execute(optional_yield y) override;
  void send_response() override;
  const char* name() const override { return "storequery_objectstatus"; }
};
