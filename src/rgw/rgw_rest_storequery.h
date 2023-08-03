// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#pragma once

#include "rgw_op.h"
#include "rgw_rest_s3.h"

/**
 * @brief Handler for StoreQuery REST commands (we only support S3).
 *
 * XXX more.
 */
class RGWHandler_REST_StoreQuery_S3 : public RGWHandler_REST_S3 {
private:
  const std::string& post_body_;

protected:
  int init_permissions(RGWOp* op, optional_yield y) override { return 0; }
  int read_permissions(RGWOp* op, optional_yield y) override { return 0; }
  bool supports_quota() override { return false; }

  /**
   * @brief Determine if a StoreQuery GET operation is being requested.
   *
   * If the x-rgw-storequery HTTP header is absent, return nullptr.
   *
   * XXX more.
   *
   * @return RGWOp* nullptr if no SQ GET operation, otherwise an RGWOp object to
   * process the operation.
   */
  RGWOp* op_get() override;
  RGWOp* op_put() override;
  RGWOp* op_delete() override;

public:
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  RGWHandler_REST_StoreQuery_S3(const rgw::auth::StrategyRegistry& auth_registry, const std::string& _post_body = "")
      : RGWHandler_REST_S3(auth_registry)
      , post_body_(_post_body)
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
   * @return true The header was successfully parsed; op() will return a
   * useful object.
   * @return false The header was not parsed, and op() will return nullptr.
   */
  bool parse(const DoutPrefixProvider* dpp, const std::string& input);
  RGWOp* op() { return op_; }
  std::string command() { return command_; }
  std::vector<std::string> param() { return param_; }
};
