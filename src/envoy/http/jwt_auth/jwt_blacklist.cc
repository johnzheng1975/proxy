#include "jwt_blacklist.h"
#include "src/envoy/http/jwt_auth/jwt.h"
#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "envoy/json/json_object.h"
#include <algorithm>
#include <stdlib.h>
#include <thread>

namespace Envoy
{
namespace Http
{
namespace JwtAuth
{

const std::string OAUTH_SERVICE = "http://hp-oauth-service.hp/";
const std::string BLACKLIST_URL = OAUTH_SERVICE + "oauth/api/v1/blacklist/access";
const std::string QUERY_PARAMETER = "?limit=1000&offset=";
const std::string BLACKLIST_API_PATH = "/oauth/api/v1/blacklist/access";
const int JWT_PAGE_SIZE = 1000;
const char  *NATS_TOPIC = "auth";
const char  *OAUTH_ACTION = "AUTH_REVOKE_ACCESS_TOKEN";
const char* ENV_NAME_OAUTH_HOST = "OAUTH_HOST";
const char* ENV_NAME_NATS_SERVERS= "NATS_URL";
const char* ENV_NAME_NATS_CLUSTER = "NATS_CLUSTER";
const char* ENV_NAME_NATS_USER = "NATS_USERNAME";
const char* ENV_NAME_NATS_PASSWORD = "NATS_PASSWORD";

JwtBlackList::JwtBlackList(Upstream::ClusterManager& cm)
   :cm_(cm)
   {
       init();
       FetchJWTBlackList();
       //connectNats(); we will postpone connect nats until we retrieve all balck list through API call
   }
JwtBlackList::~JwtBlackList(){
    ENVOY_LOG(info, "Bye, JWT Black List.");
    closeNats();
}

void JwtBlackList::init()
{
    char* oauthHost = ::getenv(ENV_NAME_OAUTH_HOST);
    if(oauthHost == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_OAUTH_HOST);
        return ;
    }
    oauthHost_ = oauthHost;
    oauthClusterName(oauthHost_, oauthClusterName_);

    char* natsServers = ::getenv(ENV_NAME_NATS_SERVERS);
    if(natsServers == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_NATS_SERVERS);
        return ;
    }
    natsServers_ = natsServers;
    
    char* natsCluster = ::getenv(ENV_NAME_NATS_CLUSTER);
    if(natsCluster == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_NATS_CLUSTER);
        return ;
    }
    natsCluster_ = natsCluster;

    char* natsUser = ::getenv(ENV_NAME_NATS_USER);
    if(natsUser == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_NATS_USER);
        return ;
    }
    natsUserName_ = natsUser;

    char* natsPassword = ::getenv(ENV_NAME_NATS_PASSWORD);
    if(natsPassword == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_NATS_PASSWORD);
        return ;
    }
    natsPassword_ = natsPassword;
}
void JwtBlackList::addRevokedJwt(const std::string& token){
    std::unique_lock<std::mutex> lock(mutex_);
    blacklist_.push_back(token);
}
// Check if JWT is in black list
bool JwtBlackList::isJwtInBlackList(const std::string &token)
{
    std::string::size_type pos = token.find_last_of('.');
    std::string signature = pos==std::string::npos?token:token.substr(pos + 1);
    std::unique_lock<std::mutex> lock(mutex_);
    return std::find(blacklist_.begin(), blacklist_.end(), signature) != blacklist_.end();
}

// Check if JWT is in black list
bool JwtBlackList::isJwtInBlackList(const Jwt &jwt)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return std::find(blacklist_.begin(), blacklist_.end(), jwt.SignatureBase64()) != blacklist_.end();
}


// Fetch a revoked JWTs.
void JwtBlackList::FetchJWTBlackList()
{
    blacklist_.clear();
//    ENVOY_LOG(info, "Fetch JWT black list started. cluster: {}, host: {}, path: {}.",
//              oauthClusterName_.c_str(), oauthHost_.c_str(), BLACKLIST_API_PATH.c_str());
    if (cm_.get(oauthClusterName_) == nullptr)
    {
        ENVOY_LOG(info, "Can not find cluster: {}", oauthClusterName_.c_str());
        return;
    }

    sendRequest();
}

void JwtBlackList::onSuccess(MessagePtr &&response)
{
    request_ = nullptr;
    uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
    if (status_code == 200)
    {
        ENVOY_LOG(info, "Fetch jwt black list [uri = {}]: got 200 ok", BLACKLIST_URL.c_str());
        std::string body;
        if (response->body())
        {
            auto len = response->body()->length();
            body = std::string(static_cast<char *>(response->body()->linearize(len)),
                               len);
            OnFetchBlacklistDone(body);
        }
        else
        {
            ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: body is empty", BLACKLIST_URL.c_str());
        }
    }
    else
    {
        ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: response status code {}", BLACKLIST_URL,
                  status_code);
    }
}
void JwtBlackList::onFailure(AsyncClient::FailureReason)
{
    request_ = nullptr;
    ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: failed", BLACKLIST_URL.c_str());
}

// Handle the public key fetch done event.
void JwtBlackList::OnFetchBlacklistDone(const std::string &body)
{
    Json::ObjectSharedPtr bodyObj;
    try
    {
        bodyObj = Json::Factory::loadFromString(body);
        int count = bodyObj->getInteger("count");
        std::vector<Json::ObjectSharedPtr> blackList = bodyObj->getObjectArray("blacklist");
        for(const auto& tokenObj: blackList){
            std::string token = tokenObj->getString("signature");
            blacklist_.push_back(token);
        }
        if(count > int(blacklist_.size())){
            sendRequest();
        }else{//We have got completed black list through API call, it is time to connect nats to reviece toke revoke message.
            connectNats();
        }
    }
    catch (Json::Exception &e)
    {
        ENVOY_LOG(info, "Parse JWT black list exception. {} ", e.what());
        return;
    }
    ENVOY_LOG(info, "Parse JWT black list finished. Total size: {}", blacklist_.size());
}

void JwtBlackList::sendRequest()
{
    char offset[32] = {'\0'};
    StringUtil::itoa(offset, sizeof(offset), blacklist_.size());
    std::string urlpath = BLACKLIST_API_PATH + QUERY_PARAMETER + offset;
    MessagePtr message(new RequestMessageImpl());
    message->headers().insertMethod().value().setReference(
        Http::Headers::get().MethodValues.Get);
    message->headers().insertPath().value(urlpath);
    message->headers().insertHost().value(oauthHost_);
    ENVOY_LOG(info, "Sending http request to fetch jwt blacklist. cluster: {}, host: {}, path: {}.",
              oauthClusterName_.c_str(), oauthHost_.c_str(), urlpath.c_str());
    request_ = cm_.httpAsyncClientForCluster(oauthClusterName_).send(std::move(message), *this, absl::optional<std::chrono::milliseconds>(10000));
}

void JwtBlackList::oauthClusterName(const std::string& oauthHost, std::string& clusterName)const
{
    auto clusters = cm_.clusters();
    for (auto &cluster : clusters)
    {
        if (cluster.first.find(oauthHost) != std::string::npos)
        {
            clusterName = cluster.first;
            break;
        }
    }
    if (clusterName.empty())
    {
        clusterName = std::string("outbound|80||") + oauthHost + ".svc.cluster.local";
    }
}

void JwtBlackList::connectNats()
{
    natsStatus      s;
    natsOptions     *opts = NULL;
    stanConnOptions *connOpts = NULL;
    stanSubOptions  *subOpts = NULL;

    if (natsOptions_Create(&opts) != NATS_OK)
        return ;

    char **serverUrls;
    int count = parseNatsServerUrls(&serverUrls);
    natsOptions_SkipServerVerification(opts, true);
    natsOptions_SetServers(opts, const_cast<const char**>(serverUrls), count);
    natsOptions_SetUserInfo(opts, natsUserName_.c_str(), natsPassword_.c_str());
    freeNatsServerUrls(serverUrls, count);

    // Now create STAN Connection Options and set the NATS Options.
    s = stanConnOptions_Create(&connOpts);
    if (s == NATS_OK)
    {   
        ENVOY_LOG(info, "create options success.");
        s = stanConnOptions_SetNATSOptions(connOpts, opts);
    }

    // Add a callback to be notified if the STAN connection is lost for good.
    if (s == NATS_OK)
    {
        ENVOY_LOG(info, "set NATS options success.");
        s = stanConnOptions_SetConnectionLostHandler(connOpts, connectionLostCB, static_cast<void*>(this));
    }

    const char* clientID = ::getenv("HOSTNAME");
    if(clientID == nullptr){
        clientID = ::getenv("hostname");
    }
    // Create the Connection using the STAN Connection Options
    if (s == NATS_OK)
        s = stanConnection_Connect(&sc_, natsCluster_.c_str(), clientID, connOpts);

    if(s == NATS_OK){
        ENVOY_LOG(info, "connect to nats success.");
    }
    if (s == NATS_OK)
    {
        s = stanSubOptions_Create(&subOpts);
    }

    // Set position
    if (s == NATS_OK)
    {
        s = stanSubOptions_StartWithLastReceived(subOpts);
    }

    // Create subscription
    if (s == NATS_OK)
    {
        s = stanConnection_Subscribe(&sub_, sc_, NATS_TOPIC, onMsg, this, subOpts);
    }
    
    if(s != NATS_OK){
        ENVOY_LOG(info, "Connect to nats failed....error: {}. nats config:[server: {}, cluster:{}, user:{}]", 
        natsStatus_GetText(s), natsServers_.c_str(), natsCluster_.c_str(), natsUserName_.c_str());
    }

    if(opts != nullptr){
        natsOptions_Destroy(opts);
    }
    if(connOpts != nullptr){
        stanConnOptions_Destroy(connOpts);
    }
    if(subOpts != nullptr){
        stanSubOptions_Destroy(subOpts);
    }

    return ;
}

void JwtBlackList::closeNats()
{
    if(sub_ != nullptr){
        stanSubscription_Close(sub_);
    }
    if(sc_ != nullptr){
        stanConnection_Close(sc_);
    }
    if( sub_ != nullptr ){
        stanSubscription_Destroy(sub_);
    }
    if( sc_!=nullptr){
        stanConnection_Destroy(sc_);
    }

    // To silence reports of memory still in-use with valgrind.
    nats_Sleep(50);
    nats_Close();
}
void JwtBlackList::onMsg(stanConnection *sc, stanSubscription *sub, const char *channel, stanMsg *msg, void *closure)
{
    UNREFERENCED_PARAMETER(sc);
    UNREFERENCED_PARAMETER(sub);
    JwtBlackList* pThis = static_cast<JwtBlackList*>(closure);
    const char* tokenMsg = stanMsg_GetData(msg);
    if(tokenMsg == nullptr){
        ENVOY_LOG(warn, "Received on {}.But message is null.", channel);
        return ;
    }
    ENVOY_LOG(info, 
           "Received on {}: sequence: {}  data: [length: {}, msg: {}], timestamp: {} redelivered: {}",
           channel,
           stanMsg_GetSequence(msg),
           stanMsg_GetDataLength(msg),
           stanMsg_GetData(msg),
           stanMsg_GetTimestamp(msg),
           stanMsg_IsRedelivered(msg) ? "yes" : "no");
    

    std::string token;
    pThis->parseNatsMsg(stanMsg_GetData(msg), token);
    if(!token.empty()){
        pThis->addRevokedJwt(token);
    }

    stanMsg_Destroy(msg);
    return ;
}

void JwtBlackList::connectionLostCB(stanConnection *sc, const char *errTxt, void *closure)
{
    UNREFERENCED_PARAMETER(sc);
    ENVOY_LOG(info, "Connection to nats clsuter lost: {}", errTxt);
    JwtBlackList* pThis = static_cast<JwtBlackList*>(closure);
    pThis->connectNats();

}
void JwtBlackList::parseNatsMsg(const char* msg, std::string& token){
    Json::ObjectSharedPtr tokenMsg;
    try
    {
        tokenMsg = Json::Factory::loadFromString(msg);
        std::string action = tokenMsg->getString("action");
        if (action == OAUTH_ACTION)
        {
            token = tokenMsg->getString("token");
        }
    }
    catch (Json::Exception &e)
    {
        ENVOY_LOG(error, "Parse token messge exception. {} ", e.what());
        return;
    }
    //ENVOY_LOG(info, "Parse token message end. Token: {}", token);
}
int JwtBlackList::parseNatsServerUrls(char*** serverUrls){
    int count = 0;
    const char* natsServers = natsServers_.c_str();
    while(*natsServers != '\0'){
        if(*natsServers++ == ',')
        {
            ++count;
        }
    }
    ++count;//
    std::string::size_type pos = 0, pos1 = 0;
    *serverUrls = new char*[count];
    int i = 0;
    while(i<count)
    {
        pos1 = natsServers_.find(",", pos);
        std::string url = natsServers_.substr(pos, (pos1!=std::string::npos) ? (pos1 - pos) : pos1);
        (*serverUrls)[i] = new char[url.size()+1];
        strcpy((*serverUrls)[i], url.c_str());
        ENVOY_LOG(info, "Nats server url [index: {}, url: {}]", i, (*serverUrls)[i]);
        ++i;
        pos = pos1 + 1;
    } 
    return count;
}
void JwtBlackList::freeNatsServerUrls(char** serverUrls, int count)
{
    for(int i = 0; i<count; ++i)
    {
        delete serverUrls[i];
    }
    delete []serverUrls;
}

} // namespace JwtAuth
} // namespace Http
} // namespace Envoy


