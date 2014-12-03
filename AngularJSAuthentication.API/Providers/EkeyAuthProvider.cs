using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AngularJSAuthentication.EkeyAuth.Provider;

namespace AngularJSAuthentication.API.Providers
{
    public class EkeyAuthProvider : EkeyAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever Ekey succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public override Task Authenticated(EkeyAuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));
            return Task.FromResult<object>(null);
        }
    }
}