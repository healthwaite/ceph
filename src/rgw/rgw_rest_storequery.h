// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#pragma once

#include "rgw_op.h"
#include "rgw_rest_s3.h"

// s3 compliant notification handler factory
class RGWHandler_REST_StoreQuery_S3 : public RGWHandler_REST_S3 {
protected:
  int init_permissions(RGWOp* op, optional_yield y) override {return 0;}
  int read_permissions(RGWOp* op, optional_yield y) override {return 0;}
  bool supports_quota() override {return false;}
  RGWOp* op_get() override;
  RGWOp* op_put() override;
  RGWOp* op_delete() override;
public:
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  virtual ~RGWHandler_REST_StoreQuery_S3() = default;

  /**
   * @brief StoreQuery custom authorization.
   *
   * XXX
   *
   * @param dpp debug prefix.
   * @param y optional yield object.
   * @return int zero on success, otherwise failure.
   */
  int authorize(const DoutPrefixProvider *dpp, optional_yield y) override;
};


class RGWStoreQueryPing : public RGWOp {
public:
  RGWStoreQueryPing() {}
  /**
   * @brief Bypass permission check.
   *
   * @param y optional yield.
   * @return int zero (success).
   */
  int verify_permission(optional_yield y) override { return 0; }

  void execute(optional_yield y) override;

  const char* name() const override { return "storequery_ping"; }
  uint32_t op_mask() override { return RGW_OP_TYPE_READ; }
};
