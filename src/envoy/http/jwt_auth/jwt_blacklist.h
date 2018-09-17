
/* Copyright 2018 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "common/common/logger.h"
#include "envoy/http/async_client.h"
#include "envoy/upstream/cluster_manager.h"
#define NATS_HAS_STREAMING
#include "nats/nats.h"
#include <mutex>
#include <condition_variable>

namespace Envoy {
namespace Http {
namespace JwtAuth {

class Jwt;
// A per-request JWT authenticator to handle all JWT authentication:
// * fetch remote public keys and cache them.
class JwtBlackList : public Logger::Loggable<Logger::Id::filter>,
                     public AsyncClient::Callbacks{
 public:
   JwtBlackList(Upstream::ClusterManager& cm);
   ~JwtBlackList();
 public:
   // initialize members from environment variableis
   void init();
   // Fetch a revoked JWTs.
   void FetchJWTBlackList();

   // Check if JWT is in black list
   bool isJwtInBlackList(const std::string& token);

   // Check if JWT is in black list
   bool isJwtInBlackList(const Jwt& jwt);
 private:
   void onSuccess(MessagePtr &&response);
   void onFailure(AsyncClient::FailureReason);

   // Handle the public key fetch done event.
   void OnFetchBlacklistDone(const std::string& body);

   void sendRequest();

   void addRevokedJwt(const std::string& token);
 private:
   void oauthClusterName(const std::string &oauthHost, std::string &clusterName) const;
   // Nats
   int parseNatsServerUrls(char*** serverUrls); 
   void freeNatsServerUrls(char** serverUrls, int count);
   void connectNats();
   void closeNats();
   void parseNatsMsg(const char* msg, std::string& token);
   static void onMsg(stanConnection *sc, stanSubscription *sub, const char *channel, stanMsg *msg, void *closure);
   static void connectionLostCB(stanConnection *sc, const char *errTxt, void *closure);

 private:
   // The cluster manager object to make HTTP call.
   Upstream::ClusterManager &cm_;

   std::vector<std::string> blacklist_;
   // The pending remote request so it can be canceled.
   AsyncClient::Request *request_{};

   std::string oauthClusterName_;
   std::string oauthHost_;

   stanConnection *sc_;
   stanSubscription *sub_;
   std::string natsCluster_;
   std::string natsServers_;
   std::string natsUserName_;
   std::string natsPassword_;

   std::mutex mutex_;
};

}  // namespace JwtAuth
}  // namespace Http
}  // namespace Envoy
