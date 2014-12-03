using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace AngularJSAuthentication.EkeyAuth.Provider
{
    public class EkeyReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public EkeyReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
       
     
    }
}