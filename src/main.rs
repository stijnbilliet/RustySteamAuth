use actix_web::{http, get, post, web, App, HttpResponse, HttpServer, Result, HttpRequest};
use serde::{Serialize, Deserialize};
use url::{Url};
use regex::Regex;

#[derive(Debug)]
pub enum Error {
    /// Often occurs due to incorrect callback link specified when creating a redirect link
    ParseUrl(url::ParseError),
    ParseQuery(serde_qs::Error),
    /// Query string conversion error when checking for validity
    Deserialize(serde_qs::Error),
    /// Error getting a SteamID64
    ParseSteamID(String),
}

#[derive(Serialize)]
struct OpenIDRequest<'a>{
    #[serde(rename = "openid.mode")] 
    mode: &'a str,
    #[serde(rename = "openid.ns")] 
    ns: &'a str,
    #[serde(rename = "openid.identity")] 
    identity: &'a str,
    #[serde(rename = "openid.claimed_id")] 
    claimed_id: &'a str,
    #[serde(rename = "openid.return_to")] 
    return_to: &'a str,
    #[serde(rename = "openid.realm")] 
    realm: &'a str,
}

#[derive(Serialize, Deserialize)]
struct OpenIDLoginData 
{
    #[serde(rename = "openid.ns")] 
    ns: String,
    #[serde(rename = "openid.mode")] 
    mode: String,
    #[serde(rename = "openid.op_endpoint")] 
    op_endpoint: String,
    #[serde(rename = "openid.claimed_id")] 
    claimed_id: String,
    #[serde(rename = "openid.identity")] 
    identity: String,
    #[serde(rename = "openid.return_to")] 
    return_to: String,
    #[serde(rename = "openid.response_nonce")] 
    response_nonce: String,
    #[serde(rename = "openid.invalidate_handle")] 
    invalidate_handle: Option<String>,
    #[serde(rename = "openid.assoc_handle")] 
    assoc_handle: String,
    #[serde(rename = "openid.signed")] 
    signed: String,
    #[serde(rename = "openid.sig")] 
    sig: String,
}

struct SteamID64
{
    user_id: u64,
}

async fn create_login_request() -> Result<Url, Error>
{
    let url = Url::parse("http://127.0.0.1:4096/auth/callback").map_err(Error::ParseUrl)?;
    //let request = LoginRequest{
    let request = OpenIDRequest {
            mode: "checkid_setup",
            ns: "http://specs.openid.net/auth/2.0",
            identity: "http://specs.openid.net/auth/2.0/identifier_select",
            claimed_id: "http://specs.openid.net/auth/2.0/identifier_select",
            return_to: &url.to_string(),
            realm: &url.origin().ascii_serialization(),
    };

    let params = serde_qs::to_string(&request).map_err(Error::ParseQuery)?;
    let mut auth_url = Url::parse("https://steamcommunity.com/openid/login").map_err(Error::ParseUrl)?;
    auth_url.set_query(Some(&params));

    println!("{}", auth_url);

    return Ok(auth_url);
}

async fn login() -> HttpResponse
{
    match create_login_request().await {
        Ok(request_url) => 
        {
            HttpResponse::TemporaryRedirect()
                .append_header((http::header::LOCATION, request_url.to_string()))
                .finish()
        },
        Err(e) =>
        {
            HttpResponse::BadRequest().body(format!("Err: {:?}", e))
        },
    }
}

async fn callback(req: HttpRequest) -> HttpResponse
{
    match verify_request(req.query_string()).await{
        Ok(v) => HttpResponse::Ok().body(format!("Hello: {}!", v.user_id)),
        Err(e) => HttpResponse::Unauthorized().body(format!("Err: {:?}", e)),
    }
}

async fn parse_claim_id(claim_uri: &String) ->Result<u64, Error>
{
    let re = Regex::new("^(http|https)://steamcommunity.com/openid/id/([0-9]{17}$)").unwrap();
    re.captures(&claim_uri)
    .ok_or(Error::ParseSteamID("Invalid claim url".to_owned()))?
    .get(2)
    .ok_or(Error::ParseSteamID("Failed to retrieve SteamID64".to_owned()))?
    .as_str()
    .parse::<u64>()
    .map_err(|e| Error::ParseSteamID(e.to_string()))
}

async fn verify_request(query_string: &str) -> Result<SteamID64, Error>
{
    let mut data = serde_qs::from_str::<OpenIDLoginData>(query_string).map_err(Error::Deserialize)?;
    data.mode = "check_authentication".to_owned();

    let claim = SteamID64
    {
        user_id: parse_claim_id(&data.claimed_id).await?,
    };

    let form = serde_qs::to_string(&data).map_err(|e| Error::ParseSteamID(e.to_string()))?;
    let client = awc::Client::default();
    let response = client
    .post("https://steamcommunity.com/openid/login")
    .send_body(form)
    .await
    .map_err(|e| Error::ParseSteamID(e.to_string()))?
    .body()
    .await
    .map_err(|e| Error::ParseSteamID(e.to_string()))?;

    let text_response = String::from_utf8(response.to_vec()).map_err(|e| Error::ParseSteamID(e.to_string()))?;

    let is_valid = text_response
        .split("\n")
        .filter_map(|line| {
            let mut pair = line.splitn(2, ":");
            Some((pair.next()?, pair.next()?))
        })
        .any(|(k, v)| k == "is_valid" && v == "true");

    if !is_valid
    {
        return Err(Error::ParseSteamID("Invalid response".to_string()));
    }

    return Ok(claim);
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    HttpServer::new(||{
        App::new()
            .service(
                web::scope("/auth")
                    .route("/login", web::get().to(login))
                    .route("/callback", web::get().to(callback))
            )
    })
    .bind(("localhost", 4096))?
    .run()
    .await
}