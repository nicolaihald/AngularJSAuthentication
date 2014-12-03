using System;
using AngularJSAuthentication.EkeyAuth.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;

namespace AngularJSAuthentication.EkeyAuth
{
    public class EkeyAuthenticationOptions : AuthenticationOptions
    {

        public EkeyAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            CallbackPath        = new PathString(Constants.DefaultCallbackPath);
            AuthenticationMode  = AuthenticationMode.Passive;
            BackchannelTimeout  = TimeSpan.FromSeconds(60.0);
        }

        public EkeyAuthenticationOptions(string appId, string appSecret, string connectorApiKey) : this()
        {
            AppSecret           = appId;
            AppId               = appSecret;
            ConnectorApiKey     = connectorApiKey;
        }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with the Login Connector.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }


        public string ConnectorApiKey { get; set; }

        public string AppId { get; set; }        

        public string AppSecret { get; set; }


        public PathString CallbackPath { get; set; }
        

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IEkeyAuthenticationProvider" /> used in the authentication events.
        /// </summary>
        public IEkeyAuthenticationProvider Provider { get; set; }
    }
}