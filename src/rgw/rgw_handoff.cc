// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/**
 * @file rgw_handoff.cc
 * @author André Lucas (andre.lucas@storageos.com)
 * @brief 'Handoff' S3 authentication engine.
 * @version 0.1
 * @date 2023-07-04
 *
 * Persistent 'helper' class for the Handoff authentication engine for S3.
 * This allows us to keep items such as a pointer to the store abstraction
 * layer and a gRPC channel around between requests.
 *
 * HandoffHelper simply wraps HandoffHelperImpl. Keep the number of classes in
 * this file to a strict minimum - most should be in rgw_handoff_impl.{h,cc}.
 */

#include "rgw_handoff.h"

// We need the impl so we can call HandoffHelperImpl's methods and can know
// the size of the object. Size is required in order to use a smart pointer to
// the implementation.
//
#include "rgw_handoff_impl.h"

#include <boost/algorithm/string.hpp>
#include <cstring>
#include <fmt/format.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include <time.h>

#include "include/ceph_assert.h"

#include "common/dout.h"
#include "rgw/rgw_http_client_curl.h"

#define dout_subsys ceph_subsys_rgw

namespace rgw {

std::ostream& operator<<(std::ostream& os, const HandoffAuthResult& r)
{
  os << r.to_string();
  return os;
}

// This has to be here, in a .cc file where we know the size of
// HandoffHelperImpl. It can't be in the header file. See
// https://www.fluentcpp.com/2017/09/22/make-pimpl-using-unique_ptr/ .
HandoffHelper::HandoffHelper()
    : impl_ {
      std::make_unique<HandoffHelperImpl>()
    }
{
}

// This has to be here, in a .cc file where we know the size of
// HandoffHelperImpl. It can't be in the header file. See
// https://www.fluentcpp.com/2017/09/22/make-pimpl-using-unique_ptr/ .
HandoffHelper::~HandoffHelper() { }

int HandoffHelper::init(CephContext* const cct, rgw::sal::Store* store)
{
  ldout(cct, 20) << "HandoffHelper::init" << dendl;
  return impl_->init(cct, store);
};

HandoffAuthResult HandoffHelper::auth(const DoutPrefixProvider* dpp,
    const std::string_view& session_token,
    const std::string_view& access_key_id,
    const std::string_view& string_to_sign,
    const std::string_view& signature,
    const req_state* const s,
    optional_yield y)
{
  return impl_->auth(dpp, session_token, access_key_id, string_to_sign, signature, s, y);
};

} /* namespace rgw */
