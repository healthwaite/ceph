// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <fmt/format.h>

#include "rgw_common.h"
#include "common/dout.h"
#include "rgw_url.h"
#include "rgw_sal_rados.h"
#include "rgw_rest_storequery.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

// // XXX is this every called? I think the op's verify_permission() override
// // might cover it.
// int RGWHandler_REST_StoreQuery_S3::authorize(const DoutPrefixProvider *dpp, optional_yield y) {
//   ldpp_dout(dpp, 20) << typeid(this).name() << ":" << __func__ << dendl;
//   return 0;
// }

static const char* SQ_HEADER = "HTTP_X_RGW_STOREQUERY";

/**
 * @brief Determine if a StoreQuery GET operation is being requested.
 *
 * The x-rgw-storequery header must first be present.
 *
 * XXX more
 *
 * @return RGWOp* nullptr if no SQ GET operation, otherwise an RGWOp object to
 * process the operation.
 */
RGWOp* RGWHandler_REST_StoreQuery_S3::op_get() {

  auto hdr = s->info.env->get(SQ_HEADER, nullptr);
  if (!hdr) {
    // Nothing to do if the x-rgw-storequery header is absent.
    return nullptr;
  }
  if (s->info.args.exists("ping")) {
    return new RGWStoreQueryPing;
  }
  return nullptr;
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_put() { return nullptr; }
RGWOp* RGWHandler_REST_StoreQuery_S3::op_delete() { return nullptr; }


void RGWStoreQueryPing::execute(optional_yield y) {
  ldpp_dout(this, 20) << fmt::format("{}: {}()", typeid(this).name(), __func__) << dendl;
}
