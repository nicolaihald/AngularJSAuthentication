using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AngularJSAuthentication.API.Entities;
using AngularJSAuthentication.API.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {

        private string _publicClientId;

        public SimpleAuthorizationServerProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException(nameof(publicClientId));
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
                context.Validated();
                //context.SetError(AuthConstants.InvalidClientId, "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (var repo = new AuthRepository())
            {
                client = repo.FindClient(context.ClientId);
            }

            if (client == null)
            {
                context.SetError(AuthConstants.InvalidClientId, string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError(AuthConstants.InvalidClientId, "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError(AuthConstants.InvalidClientId, "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError(AuthConstants.InvalidClientId, "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            context.OwinContext.Set<string>(AuthConstants.ClientAllowedOriginKey, client.AllowedOrigin);
            context.OwinContext.Set<string>(AuthConstants.ClientRefreshTokenLifeTimeKey, client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            SetAccessControlAllowOriginHeader(context.OwinContext);

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
                        AuthConstants.ClientIdKey, context.ClientId ?? string.Empty
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
            var originalClient = context.Ticket.Properties.Dictionary[AuthConstants.ClientIdKey];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError(AuthConstants.ClientIdKey, "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
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

                SetAccessControlAllowOriginHeader(context.OwinContext);


                var externalAccessTokenFromContext = context.Parameters.Get("external_access_token") ?? "";
                var externalAccessToken = externalAccessTokenFromContext.Replace(" ", "+");
                // We need the hack above because we need to take the rather weird format of the LoginConnector-tokens into account.

                var provider = context.Parameters.Get("provider") ?? "";

                if (string.IsNullOrWhiteSpace(externalAccessToken))
                {
                    context.SetError("invalid_external_accesstoken", "The external access token is invalid.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(provider))
                {
                    context.SetError("invalid_external_provider", "The external provider is invalid.");
                    return;

                }

                var verifiedAccessToken = await ExternalAccessTokenVerifier.VerifyToken(provider, externalAccessToken);
                if (verifiedAccessToken == null)
                {
                    context.SetError("invalid_external_accesstoken", "The external access token could not be verified!");
                    return;

                }
                else
                {
                    IdentityUser user;
                    using (var repo = new AuthRepository())
                    {
                        user = await repo.FindAsync(new UserLoginInfo(provider, verifiedAccessToken.user_id));
                    }


                    bool hasRegistered = user != null;
                    if (!hasRegistered)
                    {
                        context.SetError("external_user_not_registered", string.Format("The external ({0}) user is not registered. External userid: {1}", provider, verifiedAccessToken.user_id));
                        return;
                    }


                    identity.AddClaim(new Claim("urn:app:username", user.UserName ?? verifiedAccessToken.user_id));
                    identity.AddClaim(new Claim("urn:app:loginprovider", provider));
                    identity.AddClaim(new Claim("urn:app:loginproviderkey", verifiedAccessToken.user_id));
                    //identity.AddClaim(new Claim(ClaimTypes.Name, verifiedAccessToken.user_id));
                    //identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
                    //identity.AddClaim(new Claim("sub", verifiedAccessToken.user_id));

                    foreach (var claim in user.Claims)
                    {
                        identity.AddClaim(new Claim(claim.ClaimType, claim.ClaimValue));
                    }

                    var pictureClaim = user.Claims.FirstOrDefault(x => x.ClaimType == "picture");

                    var props = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        {
                            AuthConstants.ClientIdKey, context.ClientId ?? string.Empty
                        },
                        {
                            "userName", user.UserName// verifiedAccessToken.user_id
                        },

                        {
                            "LoginProvider", provider
                        },

                        {
                            "LoginProviderKey", verifiedAccessToken.user_id
                        },
                        {
                            "picture", pictureClaim != null ? pictureClaim.ClaimValue : ""
                        },
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


        private static void SetAccessControlAllowOriginHeader(IOwinContext context)
        {
            var allowedOrigin = context.Get<string>(AuthConstants.ClientAllowedOriginKey) ?? "*";

            if (!context.Response.Headers.ContainsKey(AuthConstants.AccessControlAllowOriginKey))
                context.Response.Headers.Add(AuthConstants.AccessControlAllowOriginKey, new[] { allowedOrigin });
        }
    }
}