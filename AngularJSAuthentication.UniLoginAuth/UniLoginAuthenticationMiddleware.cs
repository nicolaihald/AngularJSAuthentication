using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace AngularJSAuthentication.UniLoginAuth
{
    /* REMARKS: 
     * The dummy authentication middleware implemented is a passive one, which means that it doesn’t do anything 
     * to the incoming requests until asked so by the presence of a AuthenticationResponseChallenge. 
     */

    // One instance is created when the application starts.
    public class UniLoginAuthenticationMiddleware : AuthenticationMiddleware<UniLoginAuthenticationOptions>
    {
        public UniLoginAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, UniLoginAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(UniLoginAuthenticationMiddleware).FullName, options.AuthenticationType);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }


        // Called for each request, to create a handler for each request.
        protected override AuthenticationHandler<UniLoginAuthenticationOptions> CreateHandler()
        {
            return new UniLoginAuthenticationHandler();
        }
    }
}
