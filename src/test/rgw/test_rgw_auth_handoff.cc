// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/async/yield_context.h"
#include "common/ceph_argparse.h"
#include "common/ceph_json.h"
#include "common/dout.h"
#include "global/global_init.h"
#include "rgw/rgw_b64.h"
#include "rgw/rgw_client_io.h"
#include "rgw/rgw_handoff.h"
#include "rgw/rgw_http_client.h"
#include <boost/algorithm/hex.hpp>
#include <boost/regex.hpp>
#include <cstdint>
#include <fmt/format.h>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

/*
 * Tools tests.
 */

namespace {

/* #region(collapsed) TestData */

// The information we need to use an access key.
struct AccessKeyInfo {
  std::string userid;
  std::string secret;
};

static std::unordered_map<std::string, AccessKeyInfo>
    super_secret_vault = {
      // This is the 'testid' user created by many tests, and installed by
      // default into dbstore.
      { "0555b35654ad1656d804", { "testid", "h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==" } },
      { "AKIAIOSFODNN7EXAMPLE", { "awsquerystringexample", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } }
    };

// Look up the userid and secret for a given credential (access key id).
static std::optional<AccessKeyInfo>
info_for_credential(const std::string& access_key)
{
  auto srch = super_secret_vault.find(access_key);
  if (srch == super_secret_vault.end()) {
    return std::nullopt;
  }
  return std::make_optional(srch->second);
}

struct HandoffHdrTestData {
  std::string name;
  /// @brief The string_to_sign field.
  std::string ss_base64;
  std::string access_key;
  std::string signature;
  std::string authorization;
};

static HandoffHdrTestData sigpass_tests[]
    = {
        // This is generated by `s3cmd ls s3://test` with the bucket test
        // pre-created. V4 signature.
        {
            "s3cmd ls s3://test",
            "QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMFQxNjQ1MzJaCjIwMjMwNzEwL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNTgxYzA3NzEzYjRmODFjYmQ4YTFiN2NhN2ZiNzU4YTkyMzVmYzQyYzZjZmZjZDgyMTIxNjdiMjA2NmJjODIwMg==",
            "0555b35654ad1656d804",
            "616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230710/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
        },
        // This is generated by
        //   `dd if=/dev/urandom bs=4096 count=1 | s3cmd put - s3://test/rand1`
        // V4 signature.
        {
            "dd ... | s3cmd put - s3://test/rand1",
            "QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMVQxNDMwMTRaCjIwMjMwNzExL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNGQ1ZDg2N2NiODBmMmU3Y2FlMGM5YmZmMWUxYTE4YmYyMmJjMmY4NWYzYjVjNzY0Nzg1MTYzNTA4MjljODhkZQ",
            "0555b35654ad1656d804",
            "0c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230711/us-east-1/s3/aws4_request,SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date,Signature=0c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c" },
        // This is generated by
        //   `s3cmd ls s3://test` with nothing in the bucket.
        // V2 signature.
        {
            "s3cmd ls s3://test (empty -> v2 auth)",
            "R0VUCgoKCngtYW16LWRhdGU6VHVlLCAxMSBKdWwgMjAyMyAxNzoxMDozOCArMDAwMAovdGVzdC8=",
            "0555b35654ad1656d804",
            "ZbQ5cA54KqNak3O2KTRTwX5YzUE=",
            "AWS 0555b35654ad1656d804:ZbQ5cA54KqNak3O2KTRTwX5YzUE=" }
      };

HandoffHdrTestData sigfail_tests[]
    = {
        // This is generated by `s3cmd ls s3://test` with the bucket test
        // pre-created. V4 signature. stringToSign corrupted.
        {
            "xfail (access_key): s3cmd ls s3://test",
            "0VdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMFQxNjQ1MzJaCjIwMjMwNzEwL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNTgxYzA3NzEzYjRmODFjYmQ4YTFiN2NhN2ZiNzU4YTkyMzVmYzQyYzZjZmZjZDgyMTIxNjdiMjA2NmJjODIwMg==",
            "1555b35654ad1656d804",
            "616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230710/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
        }, // This is generated by `s3cmd ls s3://test` with the bucket test
        // pre-created. V4 signature. access_key corrupted.
        {
            "xfail (access_key): s3cmd ls s3://test",
            "QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMFQxNjQ1MzJaCjIwMjMwNzEwL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNTgxYzA3NzEzYjRmODFjYmQ4YTFiN2NhN2ZiNzU4YTkyMzVmYzQyYzZjZmZjZDgyMTIxNjdiMjA2NmJjODIwMg==",
            "1555b35654ad1656d804",
            "616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230710/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=616427c5112796fde309f6620ae2542b6c493e7c84026771d2e9f94af2b5150b",
        },
        // This is generated by
        //   `dd if=/dev/urandom bs=4096 count=1 | s3cmd put - s3://test/rand1`
        // V4 signature. Signature corrupted.
        {
            "xfail (sig): dd ... | s3cmd put - s3://test/rand1",
            "QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMVQxNDMwMTRaCjIwMjMwNzExL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNGQ1ZDg2N2NiODBmMmU3Y2FlMGM5YmZmMWUxYTE4YmYyMmJjMmY4NWYzYjVjNzY0Nzg1MTYzNTA4MjljODhkZQ",
            "0555b35654ad1656d804",
            "0c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230711/us-east-1/s3/aws4_request,SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date,Signature=1c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c" },
        // This is generated by
        //   `dd if=/dev/urandom bs=4096 count=1 | s3cmd put - s3://test/rand1`
        // V4 signature. Authorization header corrupted.
        {
            "xfail (authhdr): dd ... | s3cmd put - s3://test/rand1",
            "QVdTNC1ITUFDLVNIQTI1NgoyMDIzMDcxMVQxNDMwMTRaCjIwMjMwNzExL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QKNGQ1ZDg2N2NiODBmMmU3Y2FlMGM5YmZmMWUxYTE4YmYyMmJjMmY4NWYzYjVjNzY0Nzg1MTYzNTA4MjljODhkZQ",
            "0555b35654ad1656d804",
            "0c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c",
            "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20230711/xs-east-1/s3/aws4_request,SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date,Signature=0c7838f249db0668d832d78feb1a3fd55606dbe0e630592411c83f18ed8d465c" },
        // This is generated by
        //   `s3cmd ls s3://test` with nothing in the bucket.
        // V2 signature. stringToSign corrupted.
        {
            "xfail (v2 access key): s3cmd ls s3://test (empty -> v2 auth)",
            "00VUCgoKCngtYW16LWRhdGU6VHVlLCAxMSBKdWwgMjAyMyAxNzoxMDozOCArMDAwMAovdGVzdC8=",
            "0555b35654ad1656d804",
            "ZbQ5cA54KqNak3O2KTRTwX5YzUE=",
            "AWS 0555b35654ad1656d804:ZbQ5cA54KqNak3O2KTRTwX5YzUE=" }
      };

// This is generated by
//   `s3cmd ls s3://test` with nothing in the bucket.
// V2 signature.
HandoffHdrTestData v2_sample = {
  "v2_sample",
  "R0VUCgoKCngtYW16LWRhdGU6VHVlLCAxMSBKdWwgMjAyMyAxNzoxMDozOCArMDAwMAovdGVzdC8=",
  "0555b35654ad1656d804",
  "ZbQ5cA54KqNak3O2KTRTwX5YzUE=",
  "AWS 0555b35654ad1656d804:ZbQ5cA54KqNak3O2KTRTwX5YzUE="
};

struct HandoffQueryTestData {
  std::string name;
  std::string access_key;
  std::string presignedUrl;
};

HandoffQueryTestData presigned_pass_tests[] = {
  { "'s3cmd signurl s3://testnv/rand +3600' at 1696590328",
      "0555b35654ad1656d804",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Expires=1696593928&Signature=2yvZEGjagY%2B5nyk9IcBOR%2Bu5KT8%3D" }
};

/* #endregion */
/* #region(collapsed) SupportCode */

namespace ba = boost::algorithm;

#define SSL_CHAR_CAST(x) reinterpret_cast<const unsigned char*>(x)

static constexpr unsigned int SHA256_HASH_SIZE_BYTES = 32;

// Wrap the rigmarole of hashing a buffer with OpenSSL.
static std::optional<std::vector<uint8_t>> _hash_by(const std::vector<uint8_t>& key, const std::string& input, const std::string& hash_type)
{
  auto pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key.data(), key.size());
  auto md = EVP_get_digestbyname(hash_type.c_str());
  auto ctx = EVP_MD_CTX_new();
  if (!EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)) {
    std::cerr << "HMAC ctx init failed" << std::endl;
    return std::nullopt;
  }
  if (!EVP_DigestSignUpdate(ctx, input.data(), input.size())) {
    std::cerr << "HMAC update failed" << std::endl;
    return std::nullopt;
  }
  std::vector<uint8_t> hash(EVP_MD_size(md));
  size_t hsiz = hash.size();
  if (!EVP_DigestSignFinal(ctx, hash.data(), &hsiz) || static_cast<int>(hsiz) != EVP_MD_size(md)) {
    std::cerr << "HMAC final failed" << std::endl;
    return std::nullopt;
  }
  EVP_MD_CTX_free(ctx);
  return std::make_optional(hash);
}

// Match the fields out of the V4 Authorization header.
static boost::regex re_v4_auth { "^AWS4-HMAC-SHA256\\sCredential=(?<accesskey>[0-9a-f]+)/(?<date>\\d+)"
                                 "/(?<region>[0-9a-z-]+)"
                                 "/(?<service>[0-9a-z-]+)"
                                 "/aws4_request"
                                 ",SignedHeaders=(?<signhdr>[-;a-z0-9]+)"
                                 ",Signature=(?<sig>[0-9a-f]+)"
                                 "$" };

/* Given the inputs, generate an AWS v4 signature and return as an
 * optional<string>. In case of problems, return nullopt.
 *
 * This is the part the authenticator normally performs. Note
 * string_to_sign_b64 will be base64 encoded, as this is the way it's passed
 * to the authenticator backend by HandoffHelper.
 */
static std::optional<std::string> verify_aws_v4_signature(std::string string_to_sign_b64, std::string access_key_id, std::string secret_key, std::string authorization)
{
  // std::cerr << fmt::format("get_aws_v4_hash(): string_to_sign='{}' access_key_id='{}' secret_key='{}' authorization='{}'", string_to_sign, access_key_id, secret_key, authorization) << std::endl;

  boost::smatch m;
  if (!boost::regex_match(authorization, m, re_v4_auth)) {
    std::cerr << "no match v4" << std::endl;
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
  // Create a vec<uint8_t> of the initial secret. The _hash() function can
  // then chain input to output more easily without excessive conversions.
  std::copy(initstr.begin(), initstr.end(), std::back_inserter(init));

  // Hash each step.
  auto datekey = _hash_by(init, hdrdate, "SHA256");
  if (!datekey) {
    return std::nullopt;
  }
  auto dateregionkey = _hash_by(*datekey, hdrregion, "SHA256");
  if (!dateregionkey) {
    return std::nullopt;
  }
  auto dateregionservicekey = _hash_by(*dateregionkey, hdrservice, "SHA256");
  if (!dateregionservicekey) {
    return std::nullopt;
  }
  auto signingkey = _hash_by(*dateregionservicekey, "aws4_request", "SHA256");
  if (!signingkey) {
    return std::nullopt;
  }

  // Step 3.
  auto s2s = rgw::from_base64(string_to_sign_b64);
  auto sigbytes = _hash_by(*signingkey, s2s, "SHA256");
  if (!sigbytes) {
    return std::nullopt;
  }

  // Hex encode the signature.
  std::string sigstr;
  boost::algorithm::hex_lower(*sigbytes, std::back_inserter(sigstr));

  // Compare the signature to that in the header.
  if (sigstr != hdrsig) {
    std::cerr << fmt::format("signature mismatch got='{}' expected='{}'", sigstr, hdrsig) << std::endl;
    return std::nullopt;
  }

  return std::make_optional(sigstr);
}

// Match the fields out of the V4 Authorization header.
static boost::regex re_v2_auth { "^AWS\\s(?<accesskey>[0-9a-f]+):"
                                 "(?<sig>[^ \t]+)"
                                 "$" };

/* Given the inputs, generate an AWS v4 signature and return as an
 * optional<string>. In case of problems, return nullopt.
 *
 * This is the part the authenticator normally performs. Note string_to_sign
 * will be base64 encoded, as this is the way it's passed to the authenticator
 * backend by HandoffHelper.
 */
static std::optional<std::string> verify_aws_v2_signature(std::string string_to_sign, std::string access_key_id, std::string secret_key, std::string authorization)
{
  // std::cerr << fmt::format("get_aws_v4_hash(): string_to_sign='{}' access_key_id='{}' secret_key='{}' authorization='{}'", string_to_sign, access_key_id, secret_key, authorization) << std::endl;

  boost::smatch m;
  if (!boost::regex_match(authorization, m, re_v2_auth)) {
    std::cerr << "no match V2" << std::endl;
    return std::nullopt;
  }
  auto hdrakid = m.str("accesskey");
  auto hdrsig = m.str("sig");

  // Step 1 is in string_to_sign.

  // Step 2.
  auto initstr = secret_key;
  std::vector<uint8_t> signingkey;
  // Create a vec<uint8_t> of the initial secret. The _hash() function can
  // then chain input to output more easily without excessive conversions.
  std::copy(initstr.begin(), initstr.end(), std::back_inserter(signingkey));

  // Step 3.
  auto s2s = rgw::from_base64(string_to_sign);
  auto sigbytes = _hash_by(signingkey, s2s, "SHA1");
  if (!sigbytes) {
    return std::nullopt;
  }

  // Hex encode the signature.
  std::string sigstr;
  std::copy((*sigbytes).begin(), (*sigbytes).end(), std::back_inserter(sigstr));
  auto sig_b64 = rgw::to_base64(sigstr);

  // Compare the signature to that in the header.
  if (sig_b64 != hdrsig) {
    std::cerr << fmt::format("signature mismatch got='{}' expected='{}'", sig_b64, hdrsig) << std::endl;
    return std::nullopt;
  }

  return std::make_optional(sig_b64);
}

// Examine the Authorization header. If it starts with 'AWS ', call the v2
// signature handler. Otherwise call the v4 handler.
static std::optional<std::string> verify_aws_signature(std::string string_to_sign, std::string access_key_id, std::string secret_key, std::string authorization)
{
  if (ba::starts_with(authorization, "AWS ")) {
    return verify_aws_v2_signature(string_to_sign, access_key_id, secret_key, authorization);
  } else {
    return verify_aws_v4_signature(string_to_sign, access_key_id, secret_key, authorization);
  }
}

// Stand in for the standard verify callout, which calls the authenticator
// using HTTP. Here, we'll unpack the request and call the signature
// implementation ourselves, package a JSON response and return it in the
// provided bufferlist.
//
// As the real function, we return our result struct appropriately filled, and
// on success we put the reply markup for the caller in the bufferlist.
static rgw::HandoffVerifyResult verify_by_func(const DoutPrefixProvider* dpp, const std::string& request_json, ceph::bufferlist* resp_bl, [[maybe_unused]] optional_yield y)
{

  JSONParser parser;
  if (!parser.parse(request_json.c_str(), request_json.size())) {
    std::cerr << "Unable to parse request JSON" << std::endl;
    return rgw::HandoffVerifyResult(-EACCES, 401);
  }

  std::string string_to_sign;
  std::string access_key_id;
  std::string authorization;
  try {
    JSONDecoder::decode_json("stringToSign", string_to_sign, &parser, true);
    JSONDecoder::decode_json("accessKeyId", access_key_id, &parser, true);
    JSONDecoder::decode_json("authorization", authorization, &parser, true);

  } catch (const JSONDecoder::err& err) {
    std::cerr << "request parse error: " << err.what() << std::endl;
    return rgw::HandoffVerifyResult(-EACCES, 401);
  }

  auto info = info_for_credential(access_key_id);
  if (!info) {
    return rgw::HandoffVerifyResult(-EACCES, 404);
  }
  auto secret = (*info).secret;
  // std::cerr << fmt::format("verify_by_func(): string_to_sign='{}' access_key_id='{}' secret_key='{}' authorization='{}'", string_to_sign, access_key_id, secret, authorization) << std::endl;

  auto gen_signature = verify_aws_signature(string_to_sign, access_key_id, secret, authorization);
  std::string message;
  if (gen_signature.has_value()) {
    message = "OK";
  } else {
    return rgw::HandoffVerifyResult(-EACCES, 401);
  }

  // We only need to create the response body if we're about to return
  // success.

  JSONFormatter jf { true };
  jf.open_object_section(""); // root
  encode_json("message", message, &jf);
  encode_json("uid", (*info).userid, &jf);
  jf.close_section(); // root
  std::ostringstream oss;
  jf.flush(oss);

  resp_bl->append(oss.str());

  return rgw::HandoffVerifyResult(0, 200);
}

// Minimal client for req_state.
class TestClient : public rgw::io::BasicClient {
  RGWEnv env;

protected:
  virtual int init_env(CephContext* cct) override
  {
    return 0;
  }

public:
  virtual RGWEnv& get_env() noexcept override
  {
    return env;
  }

  virtual size_t complete_request() override
  {
    return 0;
  }
};
/* #endregion */

} // namespace

using namespace rgw;

/*
 * File-local framework tests.
 */

// Test the local signature implementation with known-good signature data.
TEST(HandoffMeta, SigPositive)
{
  for (const auto& t : sigpass_tests) {
    auto info = info_for_credential(t.access_key);
    ASSERT_TRUE(info) << "No secret found for " << t.access_key;
    auto sig = verify_aws_signature(t.ss_base64, t.access_key, (*info).secret, t.authorization);
    ASSERT_TRUE(sig);
  }
}

TEST(HandoffMeta, SigNegative)
{
  for (const auto& t : sigpass_tests) {
    auto info = info_for_credential(t.access_key);
    ASSERT_TRUE(info) << "No secret found for " << t.access_key;
    auto sig = verify_aws_signature("0" + t.ss_base64, t.access_key, (*info).secret, t.authorization);
    ASSERT_FALSE(sig);
    sig = verify_aws_signature(t.ss_base64, t.access_key, (*info).secret + "0", t.authorization);
    ASSERT_FALSE(sig);
  }
}

/*
 * HandoffHelper tests.
 */

TEST(HandoffHelper, Init)
{
  HandoffHelper hh;
  ASSERT_EQ(hh.init(g_ceph_context, nullptr), 0);
}

class HandoffHelperTest : public ::testing::Test {
protected:
  void SetUp() override
  {
    ASSERT_EQ(hh.init(g_ceph_context, nullptr), 0);
  }

  HandoffHelper hh { verify_by_func };
  optional_yield y = null_yield;
  DoutPrefix dpp { g_ceph_context, ceph_subsys_rgw, "unittest " };
};

// Don't deref if cct->cio == nullptr.
TEST_F(HandoffHelperTest, RegressNullCioPtr)
{
  auto t = sigpass_tests[0];
  RGWEnv rgw_env;
  req_state s { g_ceph_context, &rgw_env, 0 };
  auto string_to_sign = rgw::from_base64(t.ss_base64);
  auto res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
  ASSERT_EQ(res.code(), -EACCES);
  ASSERT_THAT(res.message(), testing::ContainsRegex("cio"));
}

// Fail properly when the Authorization header is absent and one can't be
// synthesized.
TEST_F(HandoffHelperTest, FailIfMissingAuthorizationHeader)
{
  TestClient cio;

  auto t = sigpass_tests[0];
  RGWEnv rgw_env;
  req_state s { g_ceph_context, &rgw_env, 0 };
  s.cio = &cio;
  auto string_to_sign = rgw::from_base64(t.ss_base64);
  auto res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
  ASSERT_EQ(res.code(), -EACCES);
  ASSERT_THAT(res.message(), testing::ContainsRegex("missing Authorization"));
}

TEST_F(HandoffHelperTest, SignatureV2CanBeDisabled)
{
  auto t = v2_sample;

  TestClient cio;
  // Set headers in the cio's env, not rgw_env (below).
  cio.get_env().set("HTTP_AUTHORIZATION", t.authorization);
  ldpp_dout(&dpp, 20) << fmt::format("Auth: {}", t.authorization) << dendl;

  RGWEnv rgw_env;
  req_state s { g_ceph_context, &rgw_env, 0 };
  s.cio = &cio;
  auto string_to_sign = rgw::from_base64(t.ss_base64);
  auto res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
  ASSERT_TRUE(res.is_ok());

  dpp.get_cct()->_conf->rgw_handoff_enable_signature_v2 = false;
  res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
  ASSERT_TRUE(res.is_err());

  dpp.get_cct()->_conf->rgw_handoff_enable_signature_v2 = true;
  res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
  ASSERT_TRUE(res.is_ok());
}

// Test working signatures with the verify_by_func handler above.
TEST_F(HandoffHelperTest, HeaderHappyPath)
{
  for (const auto& t : sigpass_tests) {
    TestClient cio;
    // Set headers in the cio's env, not rgw_env (below).
    cio.get_env().set("HTTP_AUTHORIZATION", t.authorization);
    ldpp_dout(&dpp, 20) << fmt::format("Auth: {}", t.authorization) << dendl;

    RGWEnv rgw_env;
    req_state s { g_ceph_context, &rgw_env, 0 };
    s.cio = &cio;
    auto string_to_sign = rgw::from_base64(t.ss_base64);
    auto res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
    ASSERT_TRUE(res.is_ok()) << "should pass test '" << t.name << "'";
  }
}

// Test deliberately broken signatures with the verify_by_func handler above.
TEST_F(HandoffHelperTest, HeaderExpectBadSignature)
{
  for (const auto& t : sigfail_tests) {
    TestClient cio;
    // Set headers in the cio's env, not rgw_env (below).
    cio.get_env().set("HTTP_AUTHORIZATION", t.authorization);
    ldpp_dout(&dpp, 20) << fmt::format("Auth: {}", t.authorization) << dendl;

    RGWEnv rgw_env;
    req_state s { g_ceph_context, &rgw_env, 0 };
    s.cio = &cio;
    auto string_to_sign = rgw::from_base64(t.ss_base64);
    auto res = hh.auth(&dpp, "", t.access_key, string_to_sign, t.signature, &s, y);
    ASSERT_FALSE(res.is_ok()) << "should fail test '" << t.name << "'";
  }
}

/* #region(collapsed) PresignedTestData */

struct HandoffHeaderSynthData {
  std::string name;
  std::string url;
  std::string header;
};

static HandoffHeaderSynthData synth_pass[] = {
  // All use credential 0555b35654ad1656d804, the RGW test user.

  // `aws --endpoint-url='http://amygdala-ub01.home.ae-35.com:8000' s3 presign
  // s3://testnv/rand --expires 3600`. No region.
  {
      "aws s3 GET no region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Signature=XukLh8ZYkh7LhfDNGGPEznT5qMk%3D&Expires=1697103292",
      "AWS 0555b35654ad1656d804:XukLh8ZYkh7LhfDNGGPEznT5qMk=",
  },
  // `aws --endpoint-url='http://amygdala-ub01.home.ae-35.com:8000' s3 presign
  // s3://testnv/rand --expires 3600 --region eu-west-2`. Non-default region.
  {
      "aws s3 GET with region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0555b35654ad1656d804%2F20231012%2Feu-west-2%2Fs3%2Faws4_request&X-Amz-Date=20231012T083736Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=d63f2167860f1f3a02b098988cbe9e7cf19e2d3208044e70d52bcc88985abb17",
      "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20231012/eu-west-2/s3/aws4_request, SignedHeaders=host, Signature=d63f2167860f1f3a02b098988cbe9e7cf19e2d3208044e70d52bcc88985abb17",
  },
  // `s3cmd --host http://amygdala-ub01.home.ae-35.com:8000 signurl
  // s3://testnv/rand +3600`. No region. No --host-bucket set.
  {
      "s3cmd signurl GET no region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Expires=1697103824&Signature=2X2H46QEM73dL8EAHiWTgpEUYqs%3D",
      "AWS 0555b35654ad1656d804:2X2H46QEM73dL8EAHiWTgpEUYqs=",
  },
  // `s3cmd --host http://amygdala-ub01.home.ae-35.com:8000 --region eu-west-2
  // signurl s3://testnv/rand +3600`. Non-default region. No --host-bucket
  // set. Note s3cmd didn't switch to the 'v4-ish' presigned URL format.
  {
      "s3cmd signurl GET with region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Expires=1697110701&Signature=1QoTXjLEU3oh0LTfRn5wrccgWWw%3D",
      "AWS 0555b35654ad1656d804:1QoTXjLEU3oh0LTfRn5wrccgWWw=" },
  // `presigned_url.py --endpoint http://amygdala-ub01.home.ae-35.com:8000 testnv rand get --expiry 3600`. No region.
  {
      "presigned_url.py GET no region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Signature=EqiVBEaa%2B9wUIpHUw26ph74Pq4o%3D&Expires=1697110900",
      "AWS 0555b35654ad1656d804:EqiVBEaa+9wUIpHUw26ph74Pq4o=",
  },

  // `presigned_url.py --endpoint http://amygdala-ub01.home.ae-35.com:8000
  // testnv rand get --expiry 3600 --region eu-west-2`. Non-default region.
  {
      "presigned_url.py GET with region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0555b35654ad1656d804%2F20231012%2Feu-west-2%2Fs3%2Faws4_request&X-Amz-Date=20231012T104359Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=a54b4ae7a782c395ef8a75a0fbaf23f6d4a8e6d52d06cdc358be03344dd439b4",
      "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20231012/eu-west-2/s3/aws4_request, SignedHeaders=host, Signature=a54b4ae7a782c395ef8a75a0fbaf23f6d4a8e6d52d06cdc358be03344dd439b4",
  },
  // `presigned_url.py --endpoint http://amygdala-ub01.home.ae-35.com:8000
  // testnv rand put --expiry 3600`. No region.
  {
      "presigned_url.py PUT no region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Signature=ob%2FzEMUCnhQyX1KE6vhGo0oSZq4%3D&Expires=1697107623",
      "AWS 0555b35654ad1656d804:ob/zEMUCnhQyX1KE6vhGo0oSZq4=",
  },
  // `presigned_url.py --endpoint http://amygdala-ub01.home.ae-35.com:8000
  // testnv rand put --expiry 3600 --region eu-west-2`. Non-default region.
  {
      "presigned_url.py PUT with region",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0555b35654ad1656d804%2F20231012%2Feu-west-2%2Fs3%2Faws4_request&X-Amz-Date=20231012T094852Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=cd8ed8099f8349c43bf1804bf3780ab0885e7c94baffcce65aacd34b4e6b6ade",
      "AWS4-HMAC-SHA256 Credential=0555b35654ad1656d804/20231012/eu-west-2/s3/aws4_request, SignedHeaders=host, Signature=cd8ed8099f8349c43bf1804bf3780ab0885e7c94baffcce65aacd34b4e6b6ade",
  }
};

/* #endregion */

// Make sure we're properly creating the Authorization: header from query
// parameters. This is order-dependent; however every program I've tried it
// with (s3cmd, aws s3 presign, the AWS presigned_url.py SDK example code)
// respects this order.
TEST_F(HandoffHelperTest, PresignedSynthesizeHeader)
{
  for (auto const& t : synth_pass) {

    // We need a req_state struct to pass to synthesize_auth_header(), so
    // implement the pieces of RGWHandler_REST_S3::init_from_header() that we
    // care about, taking the test URL as input.
    RGWEnv rgw_env;
    req_state s { g_ceph_context, &rgw_env, 0 };
    // In the input URL, skip to the '?' marking the start of URL parameters.
    // (This is what init_from_header() does.)
    auto p = t.url.c_str();
    for (auto c : t.url) {
      if (c == '?') {
        break;
      }
      p++;
    }
    ASSERT_TRUE(*p != 0) << t.name;
    // Parse arguments from the URL.
    s.info.args.set(p);
    s.info.args.parse(&s);
    // End init_from_header() mock.

    auto got = hh.synthesize_auth_header(&dpp, &s);
    ASSERT_TRUE(got.has_value()) << t.name;
    EXPECT_EQ(*got, t.header) << t.name;
  }
}

// #region(collapsed) PresignedExpiryData
struct PresignedExpiryData {
  std::string name;
  std::string url;
  time_t now;
  time_t delta;
};

static PresignedExpiryData expiry_unit[] = {
  {
      // Basic GET, v2 syntax (no region).
      // `s3cmd --host http://amygdala.home.ae-35.com:8000 signurl s3://testnv/rand +60`
      "s3cmd signurl +60",
      "http://amygdala-ub01.home.ae-35.com:8000/testnv/rand?AWSAccessKeyId=0555b35654ad1656d804&Expires=1697122817&Signature=2HxhmxDYl0WgfktL0L62GVC%2B9vY%3D",
      1697122757,
      60,
  },
  {
      // Basic GET, v4 syntax (region).
      // `aws --endpoint-url=http://amygdala.home.ae-35.com:8000 s3 presign
      // s3://testnv/rand --expires 60 --region eu-west-2`
      "aws s3 presign +60 region",
      "http://amygdala.home.ae-35.com:8000/testnv/rand?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0555b35654ad1656d804%2F20231012%2Feu-west-2%2Fs3%2Faws4_request&X-Amz-Date=20231012T153745Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=050fcdc4e6f7046776b36a869ad428c68ffb7dbba807af18f146ca3923b21e2f",
      1697125065,
      60,
  }
};

// #endregion

// Presigned headers have an expiry time. If we're past that time, we
// shouldn't even pass the request to the Authenticator.
TEST_F(HandoffHelperTest, PresignedCheckExpiry)
{

  for (auto const& t : expiry_unit) {

    // We need a req_state struct to pass to synthesize_auth_header(), so
    // implement the pieces of RGWHandler_REST_S3::init_from_header() that we
    // care about, taking the test URL as input.
    RGWEnv rgw_env;
    req_state s { g_ceph_context, &rgw_env, 0 };
    // In the input URL, skip to the '?' marking the start of URL parameters.
    // (This is what init_from_header() does.)
    auto p = t.url.c_str();
    for (auto c : t.url) {
      if (c == '?') {
        break;
      }
      p++;
    }
    ASSERT_TRUE(*p != 0) << t.name;
    // Parse arguments from the URL.
    s.info.args.set(p);
    s.info.args.parse(&s);
    // End init_from_header() mock.

    auto actual = hh.valid_presigned_time(&dpp, &s, t.now);
    EXPECT_EQ(actual, true) << t.name << ": expect pass (t==now)";
    actual = hh.valid_presigned_time(&dpp, &s, t.now + t.delta);
    EXPECT_EQ(actual, true) << t.name << ": expect pass (t==now+delta)";
    actual = hh.valid_presigned_time(&dpp, &s, t.now + t.delta + 1);
    EXPECT_EQ(actual, false) << t.name << ": expect fail (t==now+delta+1)";
  }
}

// main() cribbed from test_http_manager.cc

int main(int argc, char** argv)
{
  auto args = argv_to_vec(argc, argv);
  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);

  rgw_http_client_init(cct->get());
  rgw_setup_saved_curl_handles();

  // // This will raise the library logging level to max.
  // g_ceph_context->_conf->subsys.set_log_level(ceph_subsys_rgw, 20);

  ::testing::InitGoogleTest(&argc, argv);
  int r = RUN_ALL_TESTS();
  rgw_release_all_curl_handles();
  rgw_http_client_cleanup();
  return r;
}
