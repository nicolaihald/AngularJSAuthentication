using AngularJSAuthentication.API.Providers;
using AngularJSAuthentication.EkeyAuth;
using AngularJSAuthentication.UniLoginAuth;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Data.Entity;
using System.Web.Http;

[assembly: OwinStartup(typeof(AngularJSAuthentication.API.Startup))]
namespace AngularJSAuthentication.API
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions GoogleAuthOptions { get; private set; }
        public static FacebookAuthenticationOptions FacebookAuthOptions { get; private set; }

        public static EkeyAuthenticationOptions EkeyAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();

            ConfigureOAuth(app);

            WebApiConfig.Register(config);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config);

            Database.SetInitializer(new MigrateDatabaseToLatestVersion<AuthContext, AngularJSAuthentication.API.Migrations.Configuration>());

        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            //use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions
            {

            };

            var oAuthServerOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp         = true,
                TokenEndpointPath         = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                Provider                  = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider      = new SimpleRefreshTokenProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(oAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            #region --- Google Login: ---
            //Configure Google External Login
            GoogleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "659454074090-vhh7va2nd2p9ffhahs5jq72tg7k4b277.apps.googleusercontent.com",
                ClientSecret = "Xgr-lpBU8W_r7PBEE-zqNJT1",
                Provider = new GoogleAuthProvider()
            };
            app.UseGoogleAuthentication(GoogleAuthOptions);
            
            #endregion

            #region --- Facebook Login: ---
            //Configure Facebook External Login
            FacebookAuthOptions = new FacebookAuthenticationOptions()
            {
                AppId = "xxxxxx",
                AppSecret = "xxxxxx",
                Provider = new FacebookAuthProvider()
            };
            app.UseFacebookAuthentication(FacebookAuthOptions); 
            #endregion

            #region --- UNI-C Login (UniLogin): --- 
            //app.UseUniLoginAuthentication(new UniLoginAuthenticationOptions("John Doe", "42")
            //{

            //}); 
            #endregion


            EkeyAuthOptions = new EkeyAuthenticationOptions()
            {
                ConnectorApiKey = "150EA85C-1005-400A-A0AF-C5B6062B7A9D",  // LOGINCONNECTORAPIKEY (LoginConnector API-key)
                AppId           = "Ordbog",                                // Client Website Name
                AppSecret       = "ordbog20-97dd07d",                      // Client UniConn SecretKey,
                Provider = new EkeyAuthProvider()
                
            };
            app.UseEkeyAuthentication(EkeyAuthOptions);


        }
    }

}