using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AngularJSAuthentication.EkeyAuth.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AngularJSAuthentication.EkeyAuth
{
    public class EkeyAuthenticationHandler : AuthenticationHandler<EkeyAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://test-loginconnector.gyldendal.dk/api/AlreadyLoggedIn";
        private const string UserInfoEndpoint = "https://test-loginconnector.gyldendal.dk/api/LoggedInfo";
        private const string UserSubscriptionsEndpoint = "https://test-loginconnector.gyldendal.dk/api/subscriptions/GetAllSubsciptions";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public EkeyAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        // FAKE/DUMMY IMPLEMENTATION 
        //protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        //{
        //    // ASP.Net Identity requires the NameIdentitifer field to be set or it won't  
        //    // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)
        //    var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
        //    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Options.AppId, null, Options.AuthenticationType));
        //    identity.AddClaim(new Claim(ClaimTypes.Name, Options.AppSecret));

        //    var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);

        //    return Task.FromResult(new AuthenticationTicket(identity, properties));
        //}

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // TODO: CORRECT? 
                //// OAuth2 10.12 CSRF
                //if (!ValidateCorrelationId(properties, _logger))
                //{
                //    return  Task.FromResult(new AuthenticationTicket(null, properties));
                //}


                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                #region --- HOW IT SHOULD HAVE BEEN: ---
                // Build up the body for the token request
                //var body = new List<KeyValuePair<string, string>>();
                //body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                //body.Add(new KeyValuePair<string, string>("code", code));
                //body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                //body.Add(new KeyValuePair<string, string>("client_id", Options.AppId));
                //body.Add(new KeyValuePair<string, string>("client_secret", Options.AppSecret));

                //// Request the actual token:
                //HttpResponseMessage tokenResponse = await _httpClient.GetAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                //tokenResponse.EnsureSuccessStatusCode();
                //string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response:
                //dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                //string accessToken = (string)response.access_token;
                
                #endregion

                var formData = await Request.ReadFormAsync();
                var accessToken = formData["authenticationToken"];


                //
                //HttpRequestMessage alreadyLoggedInRequest = new HttpRequestMessage(HttpMethod.Get, TokenEndpoint + "?ClientName=" + Uri.EscapeDataString(Options.AppId));
                //alreadyLoggedInRequest.Headers.Add("User-Agent", "OWIN Ekey OAuth Provider");
                //alreadyLoggedInRequest.Headers.Add("LOGINCONNECTORAPIKEY", Options.ConnectorApiKey);
                ////alreadyLoggedInRequest.Headers.Add("Authorization", "BEARER " + accessToken);

                //HttpResponseMessage alreadyLoggedInResponse = await _httpClient.SendAsync(alreadyLoggedInRequest, Request.CallCancelled);
                //alreadyLoggedInResponse.EnsureSuccessStatusCode();
                //var text = await alreadyLoggedInResponse.Content.ReadAsStringAsync();
                //JObject foo = JObject.Parse(text);


                #region --- REQUEST USER INFO: ---
                var userinfoRequestData = (dynamic)new JObject();
                userinfoRequestData.subscriptionAuthentToken = accessToken;
                userinfoRequestData.clientWebShopName = Options.AppId;
                userinfoRequestData.SharedSecret = Options.AppSecret;
                //userinfoRequestData.isbn                     = null;
                //userinfoRequestData.ProductIds               = null;

                var userinfoRequest = new HttpRequestMessage(HttpMethod.Post, UserInfoEndpoint)
                {
                    Content = new StringContent(userinfoRequestData.ToString(), Encoding.UTF8, "application/json")
                };
                userinfoRequest.Headers.Add("User-Agent", "OWIN Ekey OAuth Provider");
                userinfoRequest.Headers.Add("LOGINCONNECTORAPIKEY", Options.ConnectorApiKey);

                HttpResponseMessage userinfoResponse = await _httpClient.SendAsync(userinfoRequest, Request.CallCancelled);
                userinfoResponse.EnsureSuccessStatusCode();
                var userinfoContent = await userinfoResponse.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(userinfoContent);
                
                #endregion

                #region --- REQUEST USER SUBSCRIPTIONS: ---
                var subscriptionsRequestData = (dynamic)new JObject();
                subscriptionsRequestData.subscriptionAuthentToken = accessToken;
                subscriptionsRequestData.clientWebShopName = Options.AppId;

                var subscriptionsRequest = new HttpRequestMessage(HttpMethod.Post, UserSubscriptionsEndpoint)
                {
                    Content = new StringContent(subscriptionsRequestData.ToString(), Encoding.UTF8, "application/json")
                };
                subscriptionsRequest.Headers.Add("User-Agent", "OWIN Ekey OAuth Provider");
                subscriptionsRequest.Headers.Add("LOGINCONNECTORAPIKEY", Options.ConnectorApiKey);

                HttpResponseMessage subscriptionsResponse = await _httpClient.SendAsync(subscriptionsRequest, Request.CallCancelled);
                subscriptionsResponse.EnsureSuccessStatusCode();
                var subscriptionsContent = await subscriptionsResponse.Content.ReadAsStringAsync();
                JObject subscriptions = JObject.Parse(subscriptionsContent);
                
                #endregion

                var context = new EkeyAuthenticatedContext(Context, user, subscriptions, accessToken)
                {
                    Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType)
                };


                // NOTE: ASP.Net Identity requires the NameIdentitifer field to be set or it won't  
                // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)
                
                if (!string.IsNullOrEmpty(context.UserId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.UserId, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Products))
                {
                    context.Identity.AddClaim(new Claim("urn:ekey:products", context.Products, XmlSchemaString, Options.AuthenticationType));
                }


                context.Properties = properties;


                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }

            return new AuthenticationTicket(null, properties);
        }




        /* REMARKS:
         * ============================
         * The first method to be invoked on the handler is the ApplyResponseChallengeAsync method. It will be called for all requests 
         * after the downstream middleware have been run. It is activated if two conditions are true:
         * 
         *  1) The status code is 401
         *  2) There is an AuthenticationResponseChallenge for the authentication type of the current middleware.
         *  
         * If both of these conditions are true, the dummy middleware will change the response to a redirect to the callback path.
         * If this was a real authentication middleware, it would instead be a redirect to the external authentication provider’s authentication page.
         * ============================
         */

        protected override Task ApplyResponseChallengeAsync()
        {
            // Only react to 401 if there is an authentication challenge for the authentication type of this handler.
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            
            if (challenge != null)
            {
                var baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
                var currentUri = baseUri + Request.Path + Request.QueryString;
                var redirectUri = baseUri + Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                //string scope = string.Join(" ", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);


                // (temporary hack) add state directly to the redirect uri...
                redirectUri += "?state=" + Uri.EscapeDataString(state);

                string authorizationEndpoint =
                "https://test-loginconnector.gyldendal.dk/Navigator/Navigator" +
                "?response_type=code" +
                "&clientWebSite=" + Uri.EscapeDataString(Options.AppId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&clientWsSuccessUrl=" + Uri.EscapeDataString(redirectUri) +
                "&clientWsFailureUrl=" + Uri.EscapeDataString(redirectUri) +
                //"&scope=" + Uri.EscapeDataString("DO_CONNECTOR_SUPPORT_SCOPE?") +
                "&state=" + Uri.EscapeDataString(state);

                // GOOGLE REFERENCE:
                //string authorizationEndpoint = 
                //    "https://accounts.google.com/o/oauth2/auth" +
                //    "?response_type=code" +
                //    "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                //    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                //    "&scope=" + Uri.EscapeDataString(scope) +
                //    "&state=" + Uri.EscapeDataString(state);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }


        /* 
         * The handler also monitors all incoming requests to see if it is a request for the callback path, by overriding the InvokeAsync method.
         * 
         * If the path is indeed the callback path of the authentication middleware, the AuthenticateAsync method of the base class is called. 
         * It ensures that some lazy loaded properties of the base class are loaded and then calls AuthenticateCoreAsync.
         * This is where a real handler would inspect the incoming authentication ticket from the external authentication server. 
         * The dummy middleware just creates an identity with the values from the configuration.
         */

        public override async Task<bool> InvokeAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider.
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // If the path is indeed the callback path of the authentication middleware, the AuthenticateAsync method of the base class is called.
                // It ensures that some lazy loaded properties of the base class are loaded and then calls AuthenticateCoreAsync.
                 
                // inspect the incoming authentication ticket from the external authentication server.
                var ticket = await AuthenticateAsync(); // triggers load of some lazy loaded properties, and then calls AuthenticateCoreAsync

                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }


                var context = new EkeyReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
                };

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
                
            }

            // Let the rest of the pipeline run.
            return false;
        }
    }
}