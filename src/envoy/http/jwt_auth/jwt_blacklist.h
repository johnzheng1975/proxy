
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
#include <list>

namespace Envoy {
namespace Http {
namespace JwtAuth {

typedef struct _RevokedJWT
{
  std::string token;
  long expireAt;
} RevokedJWT;

class Jwt;
// A per-request JWT authenticator to handle all JWT authentication:
// * fetch remote public keys and cache them.
class JwtBlackList : public Logger::Loggable<Logger::Id::filter>,
                     public AsyncClient::Callbacks{
 public:
   JwtBlackList(Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher);
   ~JwtBlackList();
 public:
   // Check if JWT is in black list
   bool IsJwtInBlackList(const std::string& token);

   // Check if JWT is in black list
   bool IsJwtInBlackList(const Jwt& jwt);
 private:
   //Override methods of AsyncClient::Callbacks
   void onSuccess(MessagePtr &&response);
   void onFailure(AsyncClient::FailureReason);

   //Initialize members from environment variableis
   void Init();

   void OAuthClusterName(const std::string &oauthHost, std::string &clusterName) const;
   // Fetch revoked JWTs.
   void FetchJWTBlackList();

   // Handle the public key fetch done event.
   void OnFetchBlackListDone(const std::string& body);

   void SendRequest();

   void AddRevokedJwt(const RevokedJWT& token);

 private:
   //Timer
   void CreateFetchBlackListTimer();
   void CreateCleanExpriedTokenTimer();
   void OnCleanExpiredTokenTimer();
   void OnFetchBlackListTimer();
 private:
   // Nats
   int ParseNatsServerUrls(char ***serverUrls);
   void FreeNatsServerUrls(char **serverUrls, int count);
   void ConnectNats();
   void CloseNats();
   void ParseNatsMsg(const char *msg, RevokedJWT &jwt);
   static void OnMsg(stanConnection *sc, stanSubscription *sub, const char *channel, stanMsg *msg, void *closure);
   static void ConnectionLostCB(stanConnection *sc, const char *errTxt, void *closure);

 private:
   // The cluster manager object to make HTTP call.
   Upstream::ClusterManager &cm_;

   std::list<RevokedJWT> blacklist_;
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

   Event::Dispatcher &dispatcher_;
   Event::TimerPtr clean_timer_;
   Event::TimerPtr fetch_timer_;
};
}  // namespace JwtAuth
}  // namespace Http
}  // namespace Envoy
