using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace AngularJSAuthentication.EkeyAuth
{
    public class EkeyAuthenticationHandler : AuthenticationHandler<EkeyAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        
        public EkeyAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // ASP.Net Identity requires the NameIdentitifer field to be set or it won't  
            // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)

            var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Options.AppId, null, Options.AuthenticationType));
            identity.AddClaim(new Claim(ClaimTypes.Name, Options.AppSecret));

            var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);

            return Task.FromResult(new AuthenticationTicket(identity, properties));
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
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // Only react to 401 if there is an authentication challenge for the authentication type of this handler.
                if (challenge != null)
                {
                    var state = challenge.Properties;

                    state.RedirectUri = "https://test-loginconnector.gyldendal.dk/Navigator/Navigator?clientWebSite=Ordbog&clientWsSuccessUrl=http%3A%2F%2Flocalhost%3A26264%2Fsignin-ekey&clientWsFailureUrl=http%3A%2F%2Flocalhost%3A10640%2FLoginFail.aspx";
                    
                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);

                    Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                }


                //if (challenge != null)
                //{
                //    string stringToEscape = base.get_Request().get_Scheme() + Uri.SchemeDelimiter + base.get_Request().get_Host();
                //    AuthenticationProperties properties = challenge.get_Properties();
                //    if (string.IsNullOrEmpty(properties.get_RedirectUri()))
                //    {
                //        properties.set_RedirectUri(string.Concat(new object[] { stringToEscape, base.get_Request().get_PathBase(), base.get_Request().get_Path(), base.get_Request().get_QueryString() }));
                //    }
                //    base.GenerateCorrelationId(properties);
                //    string str2 = this.BuildReturnTo(base.get_Options().StateDataFormat.Protect(properties));
                //    string redirectUri = "https://www.google.com/accounts/o8/ud?openid.ns=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0") + "&openid.ns.ax=" + Uri.EscapeDataString("http://openid.net/srv/ax/1.0") + "&openid.mode=" + Uri.EscapeDataString("checkid_setup") + "&openid.claimed_id=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0/identifier_select") + "&openid.identity=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0/identifier_select") + "&openid.return_to=" + Uri.EscapeDataString(str2) + "&openid.realm=" + Uri.EscapeDataString(stringToEscape) + "&openid.ax.mode=" + Uri.EscapeDataString("fetch_request") + "&openid.ax.type.email=" + Uri.EscapeDataString("http://axschema.org/contact/email") + "&openid.ax.type.name=" + Uri.EscapeDataString("http://axschema.org/namePerson") + "&openid.ax.type.first=" + Uri.EscapeDataString("http://axschema.org/namePerson/first") + "&openid.ax.type.last=" + Uri.EscapeDataString("http://axschema.org/namePerson/last") + "&openid.ax.required=" + Uri.EscapeDataString("email,name,first,last");
                //    GoogleApplyRedirectContext context = new GoogleApplyRedirectContext(base.get_Context(), base.get_Options(), properties, redirectUri);
                //    base.get_Options().Provider.ApplyRedirect(context);
                //}






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
                // 
                // This is where a real handler would inspect the incoming authentication ticket from the external authentication server.
                // The dummy middleware just creates an identity with the values from the configuration.

                var ticket = await AuthenticateAsync(); // triggers load of some lazy loaded properties, and then calls AuthenticateCoreAsync

                if (ticket != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);

                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }
            // Let the rest of the pipeline run.
            return false;
        }
    }
}