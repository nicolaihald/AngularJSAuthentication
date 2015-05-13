using AngularJSAuthentication.API.Entities;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AngularJSAuthentication.API.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Newtonsoft.Json.Linq;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {

        private string _publicClientId;

        public SimpleAuthorizationServerProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException("publicClientId");
            }

            _publicClientId = publicClientId;
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            string clientId;
            string clientSecret;
            Client client = null;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                //Remove the comments from the below line context.SetError, and invalidate context 
                //if you want to force sending clientId/secrects once obtain access tokens. 
                //context.Validated();
                context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (AuthRepository _repo = new AuthRepository())
            {
                client = _repo.FindClient(context.ClientId);
            }

            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == Models.ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            context.OwinContext.Set<string>("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin") ?? "*";

            //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            using (AuthRepository repo = new AuthRepository())
            {
                IdentityUser user = await repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
            identity.AddClaim(new Claim("sub", context.UserName));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "as:client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    {
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);

        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            var newClaim = newIdentity.Claims.Where(c => c.Type == "newClaim").FirstOrDefault();
            if (newClaim != null)
            {
                newIdentity.RemoveClaim(newClaim);
            }
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }



        public override async Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            if (context.GrantType == "customtype")
            {
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);

                var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin") ?? "*";
                //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });


                var externalAccessTokenFromContext = context.Parameters.Get("external_access_token") ?? "";
                var externalAccessToken = externalAccessTokenFromContext.Replace(" ", "+"); 
                // We need the hack above because we need to take the rather weird format of the LoginConnector-tokens into account.

                var provider = context.Parameters.Get("provider") ?? "";

                if (string.IsNullOrWhiteSpace(externalAccessToken))
                {
                    context.SetError("invalid_external_accesstoken", "The external access token is invalid.");
                }

                if (string.IsNullOrWhiteSpace(provider))
                {
                    context.SetError("invalid_external_provider", "The external provider is invalid.");
                }

                var verifiedAccessToken = await ExternalAccessTokenVerifier.VerifyToken(provider, externalAccessToken);
                if (verifiedAccessToken == null)
                {
                    context.SetError("invalid_external_accesstoken", "The external access token could not be verified!");
                }
                else
                {
                    IdentityUser user;
                    using (AuthRepository repo = new AuthRepository())
                    {
                        user = await repo.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));
                    }

                    //ExternalLoginInfo externalLoginInfo = await Authentication.GetExternalLoginInfoAsync();
                    ExternalLoginInfo externalLoginInfo = await context.OwinContext.Authentication.GetExternalLoginInfoAsync();

                    bool hasRegistered = user != null;

                    if (!hasRegistered)
                    {
                        context.SetError("external_user_not_registered", string.Format("The external ({0}) user is not registered. External userid: {1}", provider, verifiedAccessToken.user_id));
                        return;
                    }


                    identity.AddClaim(new Claim(ClaimTypes.Name, verifiedAccessToken.user_id));
                    identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
                    identity.AddClaim(new Claim("sub", verifiedAccessToken.user_id));

                    var props = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        {
                            "as:client_id", context.ClientId ?? string.Empty
                        },
                        {
                            "userName", verifiedAccessToken.user_id
                        }
                    });

                    var ticket = new AuthenticationTicket(identity, props);
                    context.Validated(ticket);
                }



                //context.Validated(identity);
            }

            //if (context.HasError)
            //    context.Rejected();

            await base.GrantCustomExtension(context);
        }



    }
}