using System;
using System.Globalization;
using System.Net.Http;
using AngularJSAuthentication.EkeyAuth.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using AngularJSAuthentication.EkeyAuth.Properties;

namespace AngularJSAuthentication.EkeyAuth
{
    /* REMARKS: 
     * The dummy authentication middleware implemented is a passive one, which means that it doesn’t do anything 
     * to the incoming requests until asked so by the presence of a AuthenticationResponseChallenge. 
     */

    // One instance is created when the application starts.
    public class EkeyAuthenticationMiddleware : AuthenticationMiddleware<EkeyAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;


        public EkeyAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, EkeyAuthenticationOptions options) : base(next, options)
        {
            #region --- VERIFY OPTIONS: ---
            if (String.IsNullOrWhiteSpace(options.AppId))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppId"));

            if (String.IsNullOrWhiteSpace(options.AppSecret))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppSecret"));

            if (String.IsNullOrWhiteSpace(options.ConnectorApiKey))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConnectorApiKey"));
            
            #endregion

            _logger = app.CreateLogger<EkeyAuthenticationMiddleware>();

            // fallback to default provider
            if (Options.Provider == null)
                Options.Provider = new EkeyAuthenticationProvider();

            if (string.IsNullOrEmpty(options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(EkeyAuthenticationMiddleware).FullName, options.AuthenticationType);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(options))
            {
                Timeout = options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        private HttpMessageHandler ResolveHttpMessageHandler(EkeyAuthenticationOptions options)
        {
            HttpMessageHandler handler = new WebRequestHandler();
            //HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            //// If they provided a validator, apply it or fail.
            //if (options.BackchannelCertificateValidator != null)
            //{
            //    // Set the cert validate callback
            //    var webRequestHandler = handler as WebRequestHandler;
            //    if (webRequestHandler == null)
            //    {
            //        throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
            //    }
            //    webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            //}

            return handler;
        }


        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="EkeyAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        
        protected override AuthenticationHandler<EkeyAuthenticationOptions> CreateHandler()
        {
            // Called for each request, to create a handler for each request.
            return new EkeyAuthenticationHandler(_httpClient, _logger);
        }
    }
}
