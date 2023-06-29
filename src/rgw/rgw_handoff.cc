// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_handoff.h"

#include <string>

#include "include/ceph_assert.h"

#include "common/dout.h"

#define dout_subsys ceph_subsys_rgw

namespace rgw {

  int HandoffHelper::init(CephContext *const cct) {
    ldout(cct, 20) << "HandoffHelper::init" << dendl;
    return 0; // XXX
  };

  int HandoffHelper::auth(const DoutPrefixProvider *dpp, const std::string &uid, const std::string &pwd) {
    ldpp_dout(dpp, 20) << "HandoffHelper::auth(uid='" << uid << "')" << dendl;
    return -EACCES; // XXX
  };

} /* namespace rgw */
