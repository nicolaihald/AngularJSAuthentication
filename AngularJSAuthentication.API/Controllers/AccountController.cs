using System.Text;
using AngularJSAuthentication.API.Models;
using AngularJSAuthentication.API.Results;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace AngularJSAuthentication.API.Controllers
{
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private AuthRepository _repo = null;

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        public AccountController()
        {
            _repo = new AuthRepository();
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(UserModel userModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await _repo.RegisterUser(userModel);

            IHttpActionResult errorResult = GetErrorResult(result);

            if (errorResult != null)
            {
                return errorResult;
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin


        /// <summary>
        /// 
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="error"></param>
        /// <remarks>
        /// [OverrideAuthentication]: 
        /// - Suppress global authentication filters (which suppresses the application bearer token host authentication filter). 
        /// [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]: 
        /// - Enables ExternalCookieAuthenticationType host authentication, which represents the user’s external sign in state. 
        /// With this setting, the User.Identity will be set as the external login identity, for example, Facebook identity.
        /// 
        /// [AllowAnonymous]:
        /// Enables a user to reach this endpoint without an external sign in state. 
        /// It will trigger an external sign in challenge when the user is anonymous. 
        /// That’s the scenario when the unauthorized user clicks the Google button to trigger a redirection to Facebook.com.
        ///
        /// The actual flow: 
        /// ----------------
        /// After the browser redirects back from facebook.com and gets the external sign in cookie from the Facebook authentication middleware, 
        /// this action will check if the external login data has already been associated with existing user.
        /// 
        /// If it has, it will sign in with both the application bearer token identity and the application cookie identity. 
        /// It will trigger a redirection and add an access token as an URL fragment.
        /// 
        /// If not, it will sign in with the external bearer token identity, and it will also be sent to the client by implicit flow. 
        /// The client code will check if the user is registered by the code, and display the register external user page as needed. 
        /// After the user is registered, the client code will trigger the external login flow again to get the application bearer token.
        /// </remarks>
        /// <returns></returns>
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            string redirectUri = string.Empty;

            if (error != null)
            {
                return BadRequest(Uri.EscapeDataString(error));
            }


            // If not already logged-in, just return a challenge for the specified provider. 
            // Which then will picked up by and handled by the provider middleware: 
            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            // Verify that the redirect uri is valid/allowed: 
            var redirectUriValidationResult = ValidateClientAndRedirectUri(this.Request, ref redirectUri);
            if (!string.IsNullOrWhiteSpace(redirectUriValidationResult))
            {
                return BadRequest(redirectUriValidationResult);
            }

            // verify that the "NameIdentifier"-claim matches the provider-key/issuer:
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);
            if (externalLogin == null)
            {
                return InternalServerError();
            }

            // if currently logged in using another provider, sign-out the user: 
            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            var loginInfo = await Authentication.GetExternalLoginInfoAsync();

            // verify that the user has been registered with a local account as well:
            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(externalLogin.LoginProvider, externalLogin.ProviderKey));
            bool hasRegistered = user != null;


            var state = "Nicolai";
            var stateProtected = "";

            var identity = User.Identity as ClaimsIdentity;
            var claimsToAdd = loginInfo.ExternalIdentity.Claims.ToList();

            if (hasRegistered)
            {
                var claimsToRemove = new List<Claim>();
                foreach (var claim in user.Claims.ToClaimsList(identity))
                {
                    var match = loginInfo.ExternalIdentity.Claims.FirstOrDefault(x => x.Type == claim.Type);
                    if (match != null)
                        claimsToRemove.Add(claim);
                }

                foreach (var obsoleteClaim in claimsToRemove)
                {
                    await _repo.RemoveClaimAsync(user.Id, obsoleteClaim);
                }

                foreach (var freshClaim in claimsToAdd)
                {
                    await _repo.AddClaimAsync(user.Id, freshClaim);
                }

            }
            else
            {
                state = string.Join(";", claimsToAdd.Select(x => string.Format("{0},{1}", x.Type, x.Value)).ToList());
                stateProtected = state.Protect();
            }


            //var localAccessToken = await GenerateLocalAccessTokenResponse2(externalLogin);

            redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}&state={5}",
                                           redirectUri,
                                           externalLogin.ExternalAccessToken,
                                           externalLogin.LoginProvider,
                                           hasRegistered.ToString(),
                                           externalLogin.UserName,
                                           stateProtected);

            //redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}&access_token={5}",
            //                                redirectUri,
            //                                externalLogin.ExternalAccessToken,
            //                                externalLogin.LoginProvider,
            //                                hasRegistered.ToString(),
            //                                externalLogin.UserName,
            //                                localAccessToken);

            //redirectUri = string.Format("{0}#external_access_token={1}&provider={2}&haslocalaccount={3}&external_user_name={4}",
            //                                redirectUri,
            //                                externalLogin.ExternalAccessToken,
            //                                externalLogin.LoginProvider,
            //                                hasRegistered.ToString(),
            //                                externalLogin.UserName);

            return Redirect(redirectUri);

        }

        // POST api/Account/RegisterExternal
        [AllowAnonymous]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var verifiedAccessToken = await ExternalAccessTokenVerifier.VerifyToken(model.Provider, model.ExternalAccessToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(model.Provider, verifiedAccessToken.user_id));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                return BadRequest("External user is already registered");
            }

            user = new IdentityUser() { UserName = model.UserName };

            IdentityResult result = await _repo.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            var info = new ExternalLoginInfo()
            {
                DefaultUserName = model.UserName,
                Login = new UserLoginInfo(model.Provider, verifiedAccessToken.user_id)
            };

            result = await _repo.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }


            string state = null;
            try
            {
                state = model.State.Unprotect();
            }
            catch (CryptographicException)
            {
                // Possible causes:
                // - the entropy is not the one used for encryption
                // - the data was encrypted by another user (for scope == CurrentUser)
                // - the data was encrypted on another machine (for scope == LocalMachine)
                // In this case, the stored password is not usable; just prompt the user to enter it again.
                return BadRequest("State was invalid!");

            }


            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(model.UserName + state);

            return Ok(accessTokenResponse);
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ObtainLocalAccessToken")]
        public async Task<IHttpActionResult> ObtainLocalAccessToken(string provider, string externalAccessToken)
        {

            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(externalAccessToken))
            {
                return BadRequest("Provider or external access token is not sent");
            }

            var verifiedAccessToken = await ExternalAccessTokenVerifier.VerifyToken(provider, externalAccessToken);
            if (verifiedAccessToken == null)
            {
                return BadRequest("Invalid Provider or External Access Token");
            }

            IdentityUser user = await _repo.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));

            ExternalLoginInfo externalLoginInfo = await Authentication.GetExternalLoginInfoAsync();

            bool hasRegistered = user != null;

            if (!hasRegistered)
            {
                return BadRequest("External user is not registered");
            }

            //generate access token response
            var accessTokenResponse = GenerateLocalAccessTokenResponse(user.UserName, externalLoginInfo);

            return Ok(accessTokenResponse);

        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _repo.Dispose();
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private string ValidateClientAndRedirectUri(HttpRequestMessage request, ref string redirectUriOutput)
        {

            Uri redirectUri;

            var redirectUriString = GetQueryString(Request, "redirect_uri");

            if (string.IsNullOrWhiteSpace(redirectUriString))
            {
                return "redirect_uri is required";
            }

            bool validUri = Uri.TryCreate(redirectUriString, UriKind.Absolute, out redirectUri);

            if (!validUri)
            {
                return "redirect_uri is invalid";
            }

            var clientId = GetQueryString(Request, "client_id");

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return "client_Id is required";
            }

            var client = _repo.FindClient(clientId);

            if (client == null)
            {
                return string.Format("Client_id '{0}' is not registered in the system.", clientId);
            }


            if (!string.IsNullOrEmpty(client.AllowedOrigin) && !string.Equals(client.AllowedOrigin, redirectUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
            {
                return string.Format("The given URL is not allowed by the configuration for client_id: '{0}'.", clientId);
            }

            redirectUriOutput = redirectUri.AbsoluteUri;

            return string.Empty;

        }

        private string GetQueryString(HttpRequestMessage request, string key)
        {
            var queryStrings = request.GetQueryNameValuePairs();

            if (queryStrings == null) return null;

            var match = queryStrings.FirstOrDefault(keyValue => string.Compare(keyValue.Key, key, true) == 0);

            if (string.IsNullOrEmpty(match.Value)) return null;

            return match.Value;
        }

        //private async Task<ParsedExternalAccessToken> VerifyExternalAccessToken(string provider, string accessToken)
        //{
        //    ParsedExternalAccessToken parsedToken = null;
        //    var client = new HttpClient();

        //    var verifyTokenEndPoint = "";

        //    if (provider == "Facebook")
        //    {
        //        //You can get it from here: https://developers.facebook.com/tools/accesstoken/
        //        //More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
        //        var appToken = "xxxxxx";
        //        verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);
        //    }
        //    else if (provider == "Google")
        //    {
        //        verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
        //    }
        //    else if (provider == "Ekey")
        //    {
        //        verifyTokenEndPoint =
        //            string.Format("https://test-loginconnector.gyldendal.dk/api/LoggedInfo/GetAuthInfo"); //"?access_token={0}", accessToken);

        //        // TEMP HACK:
        //        var requestData = (dynamic)new JObject();
        //        requestData.subscriptionAuthentToken = accessToken;
        //        requestData.clientWebShopName        = Startup.EkeyAuthOptions.AppId;
        //        requestData.SharedSecret             = Startup.EkeyAuthOptions.AppSecret;

        //        var loggedInfoRequest = new HttpRequestMessage(HttpMethod.Post, verifyTokenEndPoint);
        //        loggedInfoRequest.Content = new StringContent(requestData.ToString(), Encoding.UTF8, "application/json");

        //        loggedInfoRequest.Headers.Add("User-Agent", "OWIN Ekey OAuth Provider");
        //        loggedInfoRequest.Headers.Add("LOGINCONNECTORAPIKEY", Startup.EkeyAuthOptions.ConnectorApiKey);

        //        HttpResponseMessage loggedInfoResponse = await client.SendAsync(loggedInfoRequest);
        //        loggedInfoResponse.EnsureSuccessStatusCode();
        //        var text = await loggedInfoResponse.Content.ReadAsStringAsync();

        //        JObject user = JObject.Parse(text);
        //        JToken userInfo = user["UserLoggedInInfo"][0];

        //        if (userInfo != null)
        //        {
        //            var notValidatedToken = new ParsedExternalAccessToken();

        //            notValidatedToken.user_id = userInfo.Value<string>("UserIdentifier");
        //            notValidatedToken.app_id = Startup.EkeyAuthOptions.AppId;

        //            return notValidatedToken;
        //        }
        //    }
        //    else
        //    {
        //        return null;
        //    }


        //    var uri = new Uri(verifyTokenEndPoint);
        //    var response = await client.GetAsync(uri);

        //    if (response.IsSuccessStatusCode)
        //    {
        //        var content = await response.Content.ReadAsStringAsync();

        //        dynamic jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);

        //        parsedToken = new ParsedExternalAccessToken();

        //        if (provider == "Facebook")
        //        {
        //            parsedToken.user_id = jObj["data"]["user_id"];
        //            parsedToken.app_id = jObj["data"]["app_id"];

        //            if (!string.Equals(Startup.FacebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
        //            {
        //                return null;
        //            }
        //        }
        //        else if (provider == "Google")
        //        {
        //            parsedToken.user_id = jObj["user_id"];
        //            parsedToken.app_id = jObj["audience"];

        //            if (!string.Equals(Startup.GoogleAuthOptions.ClientId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
        //            {
        //                return null;
        //            }

        //        }

        //        if (provider == "Ekey")
        //        {
        //            parsedToken.user_id = jObj["UserLoggedInInfo"]["UserIdentifier"];
        //            parsedToken.app_id = jObj["UserLoggedInInfo"]["LoginProvider"];
        //            //parsedToken.app_id = jObj["UserLoggedInInfo"]["app_id"];

        //            if (!string.Equals(Startup.FacebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
        //            {
        //                return null;
        //            }
        //        }

        //    }

        //    return parsedToken;
        //}

        private JObject GenerateLocalAccessTokenResponse(string userName, ExternalLoginInfo externalLoginInfo = null)
        {

            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim("role", "user"));
            identity.AddClaim(new Claim("TODO", "urn:ekey:products"));

            if (externalLoginInfo != null)
            {
                var externalIdentity = (ClaimsIdentity)externalLoginInfo.ExternalIdentity;
                var productsClaim = externalIdentity.FindFirst("urn:ekey:products");

                if (productsClaim != null)
                    identity.AddClaim(productsClaim);
            }

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);
            var accessToken = Startup.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            JObject tokenResponse = new JObject(
                                        new JProperty("userName", userName),
                                        new JProperty("access_token", accessToken),
                                        new JProperty("token_type", "bearer"),
                                        new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
                                        new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
                                        new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString())
        );

            return tokenResponse;
        }

        private async Task<string> GenerateLocalAccessTokenResponse2(ExternalLoginData externalLoginData)
        {

            var tokenExpiration = TimeSpan.FromDays(1);


            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, externalLoginData.UserName));
            identity.AddClaim(new Claim("role", "user"));

            var claimsToInclude = externalLoginData.ExternalClaims.Where(x => x.Type.StartsWith("urn")).ToList();
            identity.AddClaims(claimsToInclude);


            // persist state during the login process, using claims: 
            var loginInfo = await Authentication.GetExternalLoginInfoAsync();
            if (loginInfo != null)
            {
                foreach (var externalClaim in loginInfo.ExternalIdentity.Claims)
                {
                    identity.AddClaim(new Claim("EXT_" + externalClaim.Type, externalClaim.Value));
                }
            }

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);
            var accessToken = Startup.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            //    JObject tokenResponse = new JObject(
            //                                new JProperty("userName", userName),
            //                                new JProperty("access_token", accessToken),
            //                                new JProperty("token_type", "bearer"),
            //                                new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()),
            //                                new JProperty(".issued", ticket.Properties.IssuedUtc.ToString()),
            //                                new JProperty(".expires", ticket.Properties.ExpiresUtc.ToString())
            //);

            return accessToken;
        }


        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }
            public string ExternalAccessToken { get; set; }

            public List<Claim> ExternalClaims { get; set; }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer) || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name),
                    ExternalAccessToken = identity.FindFirstValue("ExternalAccessToken"),
                    ExternalClaims = identity.Claims.ToList()
                };
            }
        }

        #endregion




    }

    public static class DataProtectionExtensions
    {
        public static string Protect(
            this string clearText,
            string optionalEntropy = null,
            DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            if (clearText == null)
                throw new ArgumentNullException(nameof(clearText));
            byte[] clearBytes = Encoding.UTF8.GetBytes(clearText);
            byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                ? null
                : Encoding.UTF8.GetBytes(optionalEntropy);
            byte[] encryptedBytes = ProtectedData.Protect(clearBytes, entropyBytes, scope);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static string Unprotect(
            this string encryptedText,
            string optionalEntropy = null,
            DataProtectionScope scope = DataProtectionScope.CurrentUser)
        {
            if (encryptedText == null)
                throw new ArgumentNullException(nameof(encryptedText));
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                ? null
                : Encoding.UTF8.GetBytes(optionalEntropy);
            byte[] clearBytes = ProtectedData.Unprotect(encryptedBytes, entropyBytes, scope);
            return Encoding.UTF8.GetString(clearBytes);
        }
    }
}
