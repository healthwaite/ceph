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
 * This handler is created by RGWHandler_REST_Service_S3,
 * RGWHandler_REST_Bucket_S3 and RGWHandler_REST_Obj_s3. Currently only
 * Service (for Ping) and Obj (for ObjectStatus) are in use.
 *
 * Parsing of the `x-rgw-storequery` header is delegated to class
 * RGWSQHeaderParser and the header's format is documented therein.
 *
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
   * NOTE: Our error-handling behaviour depends on exception processing in the
   * calling REST handler. RGWHandler_REST_{Service,Bucket,Obj}_S3 will catch
   * this exception, and any further handlers should have the same processing.
   * Otherwise the exception will propagate further. In v17.2.6 it will
   * terminate the process.
   *
   * If the x-rgw-storequery HTTP header is absent, return nullptr.
   *
   * If the x- header is present but its contents fail to parse, throw
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
      : RGWHandler_REST_S3(auth_registry)
      , handler_type_ { handler_type }
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
 * The header format is explained in the documentation of the parse() method.
 */
class RGWSQHeaderParser {
private:
  std::string command_ = "";
  std::vector<std::string> param_;
  RGWOp* op_ = nullptr;

public:
  RGWSQHeaderParser() { }
  /// Reset the parser object.
  void reset();
  /// @private
  /// Tokenise the header value. Intended for testing, called implicitly by
  /// parse().
  bool tokenize(const DoutPrefixProvider* dpp, const std::string& input);
  /**
   * @brief Parse the value of the `x-rgw-storequery` header and configure
   * this to return an appropriate RGWOp* object.
   *
   * The header is required to contain only ASCII-7 printable characters
   * (codes 32-127). Any rune outside this range will result in the entire
   * request being rejected.
   *
   * There is no value in allowing UTF-8 with all its processing
   * sophistication here - if a command's parameters requires a wider
   * character set, those parameters will have to be e.g. base64 encoded.
   *
   * The header contents are most 2048 bytes. This value is chosen to allow
   * for an encoding of the maximum S3 key length (1024 bytes) into some safe
   * encoding, and for some additional parameters.
   *
   * Command names are ASCII-7 strings of arbitrary length. Case is ignored in
   * the command name.
   *
   * Command parameters are not case-tranformed, as it's not possible to know
   * in advance what significance case may have to as-yet unimplemented
   * commands. If case is significant in parameters, I recommend encoding with
   * e.g. base64 as I'm disinclined to trust proxies etc. to leave HTTP
   * headers alone.
   *
   * Command parameters are space-separated. However, double-quotes are
   * respected; double-quoted parameters may contain spaces, and contained
   * double-quotes may be escaped with the sequence `\"`. This facility is
   * included to allow for straightforward commands; however it is probably
   * more wise to encode 'complex' parameters with a scheme such as base64
   * rather than deal with a quote-encoding.
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

/**
 * @brief Common behaviour for StoreQuery implementations of RGWOp.
 *
 * There are some common behavious for StoreQuery commands:
 *
 * - All bypass authorization checks (verify_requester()).
 *
 * - All bypass permission checks (verify_permission()).
 *
 * - All return RGW_OP_TYPE_READ from op_mask().
 *
 * - All force their response format to JSON (by default).
 *
 * Commands have to implement execute(), send_response_json() and name() just
 * to compile. Other methods may well be required, of course.
 *
 * If you want to return something other than JSON, you need to override
 * send_response().
 */
class RGWStoreQueryOp_Base : public RGWOp {
public:
  /**
   * @brief Bypass requester authorization checks for storequery commands.
   *
   * @param auth_registry The registry (ignored).
   * @param y optional yield.
   * @return int zero (success).
   */
  int verify_requester([[maybe_unused]] const rgw::auth::StrategyRegistry& auth_registry,
      [[maybe_unused]] optional_yield y) override
  {
    return 0;
  }
  /**
   * @brief Bypass permission checks for storequery commands.
   *
   * @param y optional yield.
   * @return int zero (success).
   */
  int verify_permission(optional_yield y) override { return 0; }
  uint32_t op_mask() override { return RGW_OP_TYPE_READ; }

  /**
   * @brief Override hook for sending a command's response JSON.
   *
   * This method must be provided by subclasses to implement their responses.
   * The minimal implementation is an empty method; that's a valid JSON
   * document, so it's a valid response. You'll still get a `content-type:
   * application/xml` header in the HTTP response, and a valid response code.
   *
   * More typically, this will actually do something, e.g.
   *
   * ```
   *   s->formatter->open_object_section("MyCommandResult");
   *   s->formatter->dump_string("my_bool", true);
   *   s->formatter->close_section();
   * ```
   *
   * It's up to the override to send valid JSON. Note Ceph::formatter handles
   * other types of output as well, notably XML, so many of its methods will
   * be no-ops on JSON.
   */
  virtual void send_response_json() = 0;

  /**
   * @brief Override of RGWOp::send_response() with our default processing. In
   * normal use, leave this method alone and override send_response_json()
   * instead.
   *
   * We change the response formatter unconditionally to JSON (normally the
   * behaviour is to default to XML but to respect the `Accept:` header or a
   * `format=` query parameter).
   *
   * All our responses will be JSON, but we recommend callers still set
   * `Accept: application/json` so error responses will also be in JSON -
   * storequery doesn't control all error responses, and if the upstream REST
   * server sends the error you'll get XML by default.
   *
   * If you want different behaviour, you can still override send_response()
   * yourself. However, to get the standard behaviour, just override
   * send_response_json() and use \p s->formatter to format your response.
   */
  void send_response();

  // `void execute(optional_yield_ y)` still required.
  // `const char* name() const` still required.

protected:
  void send_response_pre();
  void send_response_post();
};

/**
 * @brief StoreQuery ping command implementation.
 *
 * Return a copy of the user's request_id (in the header) without further
 * processing. Used to check the command path.
 *
 * ```
 * Example query: request_id 'foo', object/bucket path is ignored.
 *
 * GET /
 * ...
 * x-rgw-storequery: ping foo
 * ...
 *
 * Example response:
 * 200 OK
 *
 * With body (formatting added)
 *   <?xml version="1.0" encoding="UTF-8"?>
 *   <StoreQueryPingResult>
 *     <request_id>foo</request_id>
 *   </StoreQueryPingResult>
 * ```
 *
 * The request_id is blindly mirrored back to the caller.
 *
 * Command-specific security considerations: Since the x- header is strictly
 * canonicalised (any non-printable ASCII-7 characters will result in the
 * header's rejection) there is no concern with mirroring the request back in
 * the response document.
 */
class RGWStoreQueryOp_Ping : public RGWStoreQueryOp_Base {
private:
  std::string request_id_;

public:
  RGWStoreQueryOp_Ping(const std::string& _request_id)
      : request_id_ { _request_id }
  {
  }

  /**
   * @brief Reflect the supplied request ID back to the caller.
   *
   * Used to indicate that storequery is operational, without reference to any
   * buckets or keys.
   *
   * @param y optional yield object.
   */
  void execute(optional_yield y) override;

  /**
   * @brief Send our JSON response.
   */
  void send_response_json() override;
  const char* name() const override { return "storequery_ping"; }
};

/**
 * @brief StoreQuery ObjectStatus command implementation.
 *
 * Return the status (presence, and optionally other details) of an object in
 * the context of the existing query.
 *
 * Look fairly hard to see if an object is present on this cluster. Check:
 *
 * - 'Regular' keys in the bucket (with or without versioning enabled).
 *
 * - In versioned mode, the presence of a delete marker is taken to indicate
 *   that the key is still present on this cluster.
 *
 * - If no regular key or delete marker is present, check to see if this key
 *   is presently receiving a multipart upload, and if so mark the key as
 *   'present' even though it won't show up otherwise until the multipart
 *   upload has completed successfully.
 *
 * As a side-effect of the multipart upload implementation, if the multipart
 * upload process fails, the key will show as not present in subsequent
 * queries.
 *
 * ```
 * Example query: Get status for bucket 'test', key 'foo' whose current
 * version is of size 123 bytes.
 *
 * GET /test/foo
 * ...
 * x-rgw-storequery: objectstatus
 * ...
 *
 * Example response:
 * 200 OK
 *
 * With body (formatting added)
 *   <?xml version="1.0" encoding="UTF-8"?>
 *   <StoreQueryObjectStatusResult>
 *     <Object>
 *       <bucket>test</bucket>
 *       <key>foo</key>
 *       <deleted>false</deleted>
 *       <multipart_upload_in_progress>false</multipart_upload_in_progress>
 *       <version_id></version_id>
 *       <size>123</size>
 *     </Object>
 *   </StoreQueryObjectStatusResult>
 * ```
 *
 */
class RGWStoreQueryOp_ObjectStatus : public RGWStoreQueryOp_Base {
private:
  std::string bucket_name_;
  std::string object_key_name_;
  std::string version_id_;
  size_t object_size_;
  bool object_deleted_;
  bool object_mpuploading_;
  std::string object_mpupload_id_;

  bool execute_simple_query(optional_yield y);
  bool execute_mpupload_query(optional_yield y);

public:
  /**
   * @brief execute() Implementation - query the index for the presence of the
   * given key.
   *
   * This will first query using rgw::sal::Bucket::list() for 'regular' keys
   * (or delete markers).
   *
   * If no key is found, it will then query using
   * rgw::sal::Bucket::list_multiparts() in order to find in-flight multipart
   * uploads for the key.
   *
   * In either search, if there is a failure other than 'not found' the search
   * will be terminated and an error will be returned via \p op_ret.
   *
   * If the key is not found, \p op_ret will be set to \p -ENOENT which will
   * result in a 404 being returned to the user.
   *
   * If the key is found, \p op_ret will be zero, and barring failures
   * elsewhere in the REST server the user will receive a 200.
   *
   * @param y optional yield object.
   */
  void execute(optional_yield y) override;

  /**
   * @brief Send our JSON response.
   */
  void send_response_json() override;
  const char* name() const override { return "storequery_objectstatus"; }
};
