using AngularJSAuthentication.API.Entities;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    {

        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var clientid = context.Ticket.Properties.Dictionary["as:client_id"];

            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }

            var refreshTokenId = Guid.NewGuid().ToString("n");

            using (var repo = new AuthRepository())
            {
                var refreshTokenLifeTime = context.OwinContext.Get<string>("as:clientRefreshTokenLifeTime"); 
               
                var token = new RefreshToken() 
                { 
                    Id = Helper.GetHash(refreshTokenId),
                    ClientId = clientid, 
                    Subject = context.Ticket.Identity.Name,
                    IssuedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime)) 
                };

                context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
                context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;
                
                token.ProtectedTicket = context.SerializeTicket();

                var result = await repo.AddRefreshToken(token);

                if (result)
                {
                    context.SetToken(refreshTokenId);
                }
             
            }
        }

        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            SetAccessControlAllowOriginHeader(context.OwinContext);

            string hashedTokenId = Helper.GetHash(context.Token);

            using (var repo = new AuthRepository())
            {
                var refreshToken = await repo.FindRefreshToken(hashedTokenId);

                if (refreshToken != null )
                {
                    //Get protectedTicket from refreshToken class
                    context.DeserializeTicket(refreshToken.ProtectedTicket);

                    #region --- RELOAD USER AND REFRESH CLAIMS: ---
                    // In order to be able to reload/refresh the user, we obviously need to be able to identify the user in our underlying identity provider datastore.
                    // We're achieving this by storing this info ("LoginProvider" and "LoginProviderKey") in the AuthenticationProperties of the ticket during the authentication process.
                    // The values are added SimpleAuthorizationServerProvider.GrantCustomExtension. 

                    string loginProvider, providerKey;
                    context.Ticket.Properties.Dictionary.TryGetValue("LoginProvider", out loginProvider);
                    context.Ticket.Properties.Dictionary.TryGetValue("LoginProviderKey", out providerKey);

                    var identity = context.Ticket.Identity;
                    AuthenticationTicket newTicket = null;

                    if (loginProvider != null)
                    {
                        var user = await repo.FindAsync(new UserLoginInfo(loginProvider, providerKey));
                        if (user != null)
                        {
                            var userClaims = identity.Claims.ToList();
                            for (int i = 0; i < userClaims.Count; i++)
                            {
                                identity.RemoveClaim(userClaims[i]);
                            }
                            // refresh claims 
                            identity.AddClaims(user.Claims.ToClaimsList(identity));
                            identity.AddClaim(new Claim("REFRESH_TOKEN_TIMESTAMP", DateTimeOffset.UtcNow.ToString()));
                        }
                    }

                    newTicket = new AuthenticationTicket(identity, context.Ticket.Properties);
                    context.SetTicket(newTicket);
                    #endregion

                    var result = await repo.RemoveRefreshToken(hashedTokenId);
                }
            }
        }

        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }


        private static void SetAccessControlAllowOriginHeader(IOwinContext context)
        {
            var allowedOrigin = context.Get<string>("as:clientAllowedOrigin") ?? "*";

            const string allowOriginHeaderKey = "Access-Control-Allow-Origin";
            if (!context.Response.Headers.ContainsKey(allowOriginHeaderKey))
                context.Response.Headers.Add(allowOriginHeaderKey, new[] { allowedOrigin });
        }
    }
}