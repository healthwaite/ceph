// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/ceph_argparse.h"
#include "global/global_init.h"
#include "rgw/rgw_b64.h"
#include "rgw/rgw_handoff.h"
#include "rgw/rgw_http_client.h"
#include <boost/algorithm/hex.hpp>
#include <boost/regex.hpp>
#include <cstdint>
#include <fmt/format.h>
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/hmac.h>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

#define SSL_CHAR_CAST(x) reinterpret_cast<const unsigned char*>(x)

static constexpr unsigned int SHA256_HASH_SIZE_BYTES = 32;

// Wrap the rigmarole of hashing a buffer with OpenSSL.
std::optional<std::vector<uint8_t>> _hash(const std::vector<uint8_t>& key, std::string input)
{
  auto ctx = HMAC_CTX_new();
  if (!HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), NULL)) {
    std::cerr << "HMAC ctx init failed" << std::endl;
    return std::nullopt;
  }
  HMAC_Update(ctx, SSL_CHAR_CAST(input.data()), input.length());
  std::vector<uint8_t> hash(SHA256_HASH_SIZE_BYTES);
  unsigned int hsiz;
  if (!HMAC_Final(ctx, hash.data(), &hsiz) || (int)hsiz != EVP_MD_size(EVP_sha256())) {
    std::cerr << "HMAC final failed" << std::endl;
    return std::nullopt;
  }
  return std::make_optional(hash);
}

/* Given the inputs, generate an AWS v4 signature and return as an
 * optional<string>. In case of problems, return nullopt.
 *
 * This is the part the authenticator normally performs. Note string_to_sign
 * will be base64 encoded, as this is the way it's passed to the authenticator
 * backend by HandoffHelper.
 */
std::optional<std::string> get_aws_v4_hash(std::string string_to_sign, std::string access_key_id, std::string secret_key, std::string authorization)
{

  boost::regex re_auth { "^AWS4-HMAC-SHA256\\sCredential=(?<accesskey>[0-9a-f]+)/(?<date>\\d+)"
                         "/(?<region>[0-9a-z-]+)"
                         "/(?<service>[0-9a-z-]+)"
                         "/aws4_request"
                         ",SignedHeaders=(?<signhdr>[-;a-z0-9]+)"
                         ",Signature=(?<sig>[0-9a-f]+)"
                         "$" };
  boost::smatch m;
  if (!boost::regex_match(authorization, m, re_auth)) {
    std::cerr << "no match" << std::endl;
    return std::nullopt;
  }
  auto hdrakid = m.str("accesskey");
  auto hdrdate = m.str("date");
  auto hdrregion = m.str("region");
  auto hdrservice = m.str("service");
  auto hdrsig = m.str("sig");

  // Step 1 is in string_to_sign.

  // Step 2.
  auto initstr = "AWS4" + secret_key;
  std::vector<uint8_t> init;
  // Create a vec<uint8_t> of the initial secret. The _hash() function can then
  // chain input to output more easily without excessive conversions.
  std::copy(initstr.begin(), initstr.end(), std::back_inserter(init));

  // Hash each step.
  auto datekey = _hash(init, hdrdate);
  if (!datekey) {
    return std::nullopt;
  }
  auto dateregionkey = _hash(*datekey, hdrregion);
  if (!dateregionkey) {
    return std::nullopt;
  }
  auto dateregionservicekey = _hash(*dateregionkey, hdrservice);
  if (!dateregionservicekey) {
    return std::nullopt;
  }
  auto signingkey = _hash(*dateregionservicekey, "aws4_request");
  if (!signingkey) {
    return std::nullopt;
  }

  // Step 3.
  auto s2s = rgw::from_base64(string_to_sign);
  auto sigbytes = _hash(*signingkey, s2s);
  if (!sigbytes) {
    return std::nullopt;
  }

  // Hex encode the signature.
  std::string sigstr;
  boost::algorithm::hex_lower(*sigbytes, std::back_inserter(sigstr));

  // Compare the signature to that in the header.
  if (sigstr != hdrsig) {
    std::cerr << "signature mismatch" << std::endl;
    return std::nullopt;
  }

  return std::make_optional(sigstr);
}

} // namespace

using namespace rgw;

TEST(HandoffMeta, Sig)
{
  auto sig = get_aws_v4_hash("QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMFQxNjQ1MzJaCjIwMjMwNzEwL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNTgxYzA3NzEzYjRmODFjYmQ4YTFiN2NhN2ZiNzU4YTkyMzVmYzQyYzZjZmZjZDgyMTIxNjdiMjA2NmJjODIwMg==",
      "0555b35654ad1656d804",
      "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==",
      "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230710/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b");
  ASSERT_TRUE(sig.has_value());
}

TEST(HandoffHelper, Init)
{
  HandoffHelper hh;
  ASSERT_EQ(hh.init(g_ceph_context), 0);
}

// main() cribbed from test_http_manager.cc

int main(int argc, char** argv)
{
  auto args = argv_to_vec(argc, argv);
  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);

  rgw_http_client_init(cct->get());
  rgw_setup_saved_curl_handles();
  ::testing::InitGoogleTest(&argc, argv);
  int r = RUN_ALL_TESTS();
  rgw_release_all_curl_handles();
  rgw_http_client_cleanup();
  return r;
}
