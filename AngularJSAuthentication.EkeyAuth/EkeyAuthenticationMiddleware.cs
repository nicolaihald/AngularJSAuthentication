using System;
using System.Globalization;
using System.Net.Http;
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
            // verify options
            if (String.IsNullOrWhiteSpace(options.AppId))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppId"));

            if (String.IsNullOrWhiteSpace(options.AppSecret))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppSecret"));

            if (String.IsNullOrWhiteSpace(options.ConnectorApiKey))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConnectorApiKey"));

            // 
            _logger = app.CreateLogger<EkeyAuthenticationMiddleware>();


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
                //Timeout = options.BackchannelTimeout,
                //MaxResponseContentBufferSize = 1024 * 1024 * 10
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


        // Called for each request, to create a handler for each request.
        protected override AuthenticationHandler<EkeyAuthenticationOptions> CreateHandler()
        {
            return new EkeyAuthenticationHandler(_httpClient, _logger);
        }
    }
}
