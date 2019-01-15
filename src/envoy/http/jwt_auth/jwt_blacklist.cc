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

const std::string OAUTH_SERVICE = "http://hp-oauth-service.hp";
const std::string BLACKLIST_API_PATH = "/oauth/api/v1/blacklist/access";
const std::string BLACKLIST_URL = OAUTH_SERVICE + BLACKLIST_API_PATH;
const std::string QUERY_PARAMETER = "?limit=1000&offset=";
const char  *NATS_TOPIC = "auth";
const char  *OAUTH_ACTION = "AUTH_REVOKE_ACCESS_TOKEN";
const char* ENV_NAME_OAUTH_HOST = "OAUTH_HOST";
const char* ENV_NAME_NATS_SERVERS= "NATS_URL";
const char* ENV_NAME_NATS_CLUSTER = "NATS_CLUSTER";
const char* ENV_NAME_NATS_USER = "NATS_USERNAME";
const char* ENV_NAME_NATS_PASSWORD = "NATS_PASSWORD";
const std::chrono::milliseconds FETCH_INTERVAL(5000);
const std::chrono::milliseconds CLEAN_INTERVAL(600000);

JwtBlackList::JwtBlackList(Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher)
   :cm_(cm),dispatcher_(dispatcher)
   {
       Init();
       FetchJWTBlackList();
       //connectNats(); we will postpone the connection to nats until we retrieve all revoked tokens through API call
   }
JwtBlackList::~JwtBlackList(){
    ENVOY_LOG(info, "Bye, JWT Black List.");
    CloseNats();
}

void JwtBlackList::Init()
{
    char* oauthHost = ::getenv(ENV_NAME_OAUTH_HOST);
    if(oauthHost == nullptr){
        ENVOY_LOG(error, "Environment variable {} is missing.", ENV_NAME_OAUTH_HOST);
        return ;
    }
    oauthHost_ = oauthHost;
    OAuthClusterName(oauthHost_, oauthClusterName_);

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

    CreateCleanExpriedTokenTimer();
}

void JwtBlackList::AddRevokedJwt(const RevokedJWT& token){
    std::unique_lock<std::mutex> lock(mutex_);
    blacklist_.push_back(token);
}
// Check if a JWT is in black list
bool JwtBlackList::IsJwtInBlackList(const std::string &token)
{
    std::string::size_type pos = token.find_last_of('.');
    std::string signature = pos==std::string::npos?token:token.substr(pos + 1);
    std::unique_lock<std::mutex> lock(mutex_);
    return blacklist_.end() != std::find_if(blacklist_.begin(), blacklist_.end(),
                        [&signature](const RevokedJWT &jwt) { return jwt.token == signature; });
}

// Check if a JWT is in black list
bool JwtBlackList::IsJwtInBlackList(const Jwt &jwt)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return blacklist_.end() != std::find_if(blacklist_.begin(), blacklist_.end(),
                        [&jwt](const RevokedJWT &reovkedJwt) { return reovkedJwt.token == jwt.SignatureBase64(); });
}


// Fetch revoked JWTs.
void JwtBlackList::FetchJWTBlackList()
{
    blacklist_.clear();
//    ENVOY_LOG(info, "Fetch JWT black list started. cluster: {}, host: {}, path: {}.",
//              oauthClusterName_.c_str(), oauthHost_.c_str(), BLACKLIST_API_PATH.c_str());
    if (cm_.get(oauthClusterName_) == nullptr)
    {
        ENVOY_LOG(info, "Can not find cluster: {}. Starting a timer to fetch blacklist.", oauthClusterName_.c_str());
        CreateFetchBlackListTimer();
        return;
    }

    SendRequest();
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
            body = std::string(static_cast<char *>(response->body()->linearize(len)),len);
            OnFetchBlackListDone(body);
        }
        else
        {
            ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: body is empty", BLACKLIST_URL.c_str());
        }
    }
    else
    {
        CreateFetchBlackListTimer();
        ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: response status code {}", BLACKLIST_URL,
                  status_code);
    }
}
void JwtBlackList::onFailure(AsyncClient::FailureReason)
{
    request_ = nullptr;
    CreateFetchBlackListTimer();
    ENVOY_LOG(error, "Fetch jwt black list [uri = {}]: failed", BLACKLIST_URL.c_str());
}

// Handle the public key fetch done event.
void JwtBlackList::OnFetchBlackListDone(const std::string &body)
{
    Json::ObjectSharedPtr bodyObj;
    try
    {
        bodyObj = Json::Factory::loadFromString(body);
        int count = bodyObj->getInteger("count");
        std::vector<Json::ObjectSharedPtr> blackList = bodyObj->getObjectArray("blacklist");
        for(const auto& tokenObj: blackList){
            RevokedJWT jwt;
            jwt.token = tokenObj->getString("signature");
            jwt.expireAt = tokenObj->getInteger("expire_at");
            blacklist_.push_back(jwt);
        }
        if(count > int(blacklist_.size())){
            SendRequest();
        }else{//We have got completed black list through API call, it is time to connect nats to reviece toke revoke message.
            ConnectNats();
        }
    }
    catch (Json::Exception &e)
    {
        ENVOY_LOG(info, "Parse JWT black list exception. {} ", e.what());
        return;
    }
    ENVOY_LOG(info, "Parse JWT black list finished. Total size: {}", blacklist_.size());
}

void JwtBlackList::SendRequest()
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

void JwtBlackList::OAuthClusterName(const std::string& oauthHost, std::string& clusterName)const
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

void JwtBlackList::ConnectNats()
{
    natsStatus      s;
    natsOptions     *opts = NULL;
    stanConnOptions *connOpts = NULL;
    stanSubOptions  *subOpts = NULL;

    if (natsOptions_Create(&opts) != NATS_OK)
        return ;

    char **serverUrls;
    int count = ParseNatsServerUrls(&serverUrls);
    natsOptions_SkipServerVerification(opts, true);
    natsOptions_SetServers(opts, const_cast<const char**>(serverUrls), count);
    natsOptions_SetUserInfo(opts, natsUserName_.c_str(), natsPassword_.c_str());
    FreeNatsServerUrls(serverUrls, count);

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
        s = stanConnOptions_SetConnectionLostHandler(connOpts, ConnectionLostCB, static_cast<void*>(this));
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
        s = stanConnection_Subscribe(&sub_, sc_, NATS_TOPIC, OnMsg, this, subOpts);
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

void JwtBlackList::CloseNats()
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
void JwtBlackList::OnMsg(stanConnection *sc, stanSubscription *sub, const char *channel, stanMsg *msg, void *closure)
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
    

    RevokedJWT jwt;
    pThis->ParseNatsMsg(stanMsg_GetData(msg), jwt);
    if(!jwt.token.empty()){
        pThis->AddRevokedJwt(jwt);
    }

    stanMsg_Destroy(msg);
    return ;
}

void JwtBlackList::ConnectionLostCB(stanConnection *sc, const char *errTxt, void *closure)
{
    UNREFERENCED_PARAMETER(sc);
    ENVOY_LOG(warn, "Connection to nats clsuter lost: {}", errTxt);
    JwtBlackList* pThis = static_cast<JwtBlackList*>(closure);
    pThis->ConnectNats();

}
void JwtBlackList::ParseNatsMsg(const char* msg, RevokedJWT& jwt){
    Json::ObjectSharedPtr tokenMsg;
    try
    {
        tokenMsg = Json::Factory::loadFromString(msg);
        std::string action = tokenMsg->getString("action");
        if (action == OAUTH_ACTION)
        {
            jwt.token = tokenMsg->getString("token");
            if(tokenMsg->hasObject("token_expiration")) {
                jwt.expireAt = tokenMsg->getInteger("token_expiration");
            }
            else{
                jwt.expireAt = time(nullptr)+24*3600;
                ENVOY_LOG(info, "NATS message does not include \"token_expiration\", set the expireAt to  {} ", jwt.expireAt);
            }
        }
    }
    catch (Json::Exception &e)
    {
        ENVOY_LOG(error, "Parse token messge exception. {} ", e.what());
        return;
    }
    //ENVOY_LOG(info, "Parse token message end. Token: {}", token);
}
int JwtBlackList::ParseNatsServerUrls(char*** serverUrls){
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
void JwtBlackList::FreeNatsServerUrls(char** serverUrls, int count)
{
    for(int i = 0; i<count; ++i){
        delete serverUrls[i];
    }
    delete []serverUrls;
}

/***************Timer****************/
void JwtBlackList::CreateFetchBlackListTimer(){
    if(fetch_timer_ == nullptr){
        fetch_timer_ = dispatcher_.createTimer([this]() {
            OnFetchBlackListTimer();
        });
    }
    if (fetch_timer_ != nullptr){
        fetch_timer_->enableTimer(FETCH_INTERVAL);
    }
}
void JwtBlackList::CreateCleanExpriedTokenTimer(){
    clean_timer_ = dispatcher_.createTimer([this]() {
        OnCleanExpiredTokenTimer();
    });
    if (clean_timer_ != nullptr){
        clean_timer_ ->enableTimer(CLEAN_INTERVAL);
    }
}
void JwtBlackList::OnFetchBlackListTimer(){
    ENVOY_LOG(info, "Start to fetch black list in timer.");
    fetch_timer_->disableTimer();

    FetchJWTBlackList();
}
void JwtBlackList::OnCleanExpiredTokenTimer(){
    ENVOY_LOG(info, "Start to clean expired token. Current tokens count: {}", blacklist_.size());
    std::unique_lock<std::mutex> lock(mutex_);
    for(auto it = blacklist_.begin(); it != blacklist_.end(); ){
        const RevokedJWT& jwt = *it;
        if(jwt.expireAt<=time(nullptr)){
            it = blacklist_.erase(it);
        }else{
            ++it;
        }
    }
    clean_timer_->enableTimer(CLEAN_INTERVAL);
    ENVOY_LOG(info, "End clean expired token. Current tokens count: {}", blacklist_.size());
}

} // namespace JwtAuth
} // namespace Http
} // namespace Envoy


