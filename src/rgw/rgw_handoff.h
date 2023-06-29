// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#ifndef RGW_HANDOFF_H
#define RGW_HANDOFF_H

#include "acconfig.h"

#include "common/ceph_context.h"
#include "common/dout.h"

#include <string>

namespace rgw {

/**
 * @brief Support class for 'handoff' authentication.
 */
class HandoffHelper {
    std::string uri_;

public:

    HandoffHelper(std::string _uri) : uri_(std::move(_uri)) {
        // XXX
     }
    ~HandoffHelper() {
        // XXX
     }

    int init(CephContext *const cct);
    int auth(const DoutPrefixProvider *dpp, const std::string &uid, const std::string &pwd);
};

} /* namespace rgw */

#endif /* RGW_HANDOFF_H */
