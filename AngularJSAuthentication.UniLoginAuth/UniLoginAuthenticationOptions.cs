using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;

namespace AngularJSAuthentication.UniLoginAuth
{
    public class UniLoginAuthenticationOptions : AuthenticationOptions
    {
        public UniLoginAuthenticationOptions(string userName, string userId) : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            CallbackPath        = new PathString(Constants.DefaultCallbackPath);
            AuthenticationMode  = AuthenticationMode.Passive;
            UserName            = userName;
            UserId              = userId;
        }

        public PathString CallbackPath { get; set; }

        public string UserName { get; set; }

        public string UserId { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}