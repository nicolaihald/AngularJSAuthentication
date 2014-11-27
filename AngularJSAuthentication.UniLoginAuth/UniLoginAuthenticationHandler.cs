using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace AngularJSAuthentication.UniLoginAuth
{
    public class UniLoginAuthenticationHandler : AuthenticationHandler<UniLoginAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // ASP.Net Identity requires the NameIdentitifer field to be set or it won't  
            // accept the external login (AuthenticationManagerExtensions.GetExternalLoginInfo)

            var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Options.UserId, null, Options.AuthenticationType));
            identity.AddClaim(new Claim(ClaimTypes.Name, Options.UserName));

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

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);

                    Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                }
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