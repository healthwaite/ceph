// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_common.h"
#include "common/dout.h"
#include "rgw_url.h"
#include "rgw_sal_rados.h"
#include "rgw_rest_storequery.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

int RGWHandler_REST_StoreQuery_S3::authorize(const DoutPrefixProvider *dpp, optional_yield y) {
    ldpp_dout(dpp, 20) << typeid(this).name() << ":" << __PRETTY_FUNCTION__ << dendl;
    return 0;
}

RGWOp* RGWHandler_REST_StoreQuery_S3::op_get() { return nullptr; }
RGWOp* RGWHandler_REST_StoreQuery_S3::op_put() { return nullptr; }
RGWOp* RGWHandler_REST_StoreQuery_S3::op_delete() { return nullptr; }


void RGWStoreQueryPing::execute(optional_yield y) {

}
