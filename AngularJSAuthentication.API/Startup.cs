using System;
using System.Data.Entity;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using AngularJSAuthentication.API;
using AngularJSAuthentication.API.Migrations;
using AngularJSAuthentication.API.Providers;
using AngularJSAuthentication.EkeyAuth;
using AngularJSAuthentication.EkeyAuth.Provider;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(Startup))]
namespace AngularJSAuthentication.API
{
    public class Startup
    {

        public static OAuthAuthorizationServerOptions OAuthServerOptions { get; private set; }

        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions GoogleAuthOptions { get; private set; }
        public static FacebookAuthenticationOptions FacebookAuthOptions { get; private set; }

        public static EkeyAuthenticationOptions EkeyAuthOptions { get; private set; }

        public static ISecureDataFormat<AuthenticationTicket> TicketDataProtector { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();


            ConfigureOAuth(app);
            WebApiConfig.Register(config);
            app.UseWebApi(config);

            Database.SetInitializer(new MigrateDatabaseToLatestVersion<AuthContext, Configuration>());

        }



        public void ConfigureOAuth(IAppBuilder app)
        {
            // only used for protecting temporary tickets/state passed back and forth between the client and the server during the login registration process. 
            TicketDataProtector = new TicketDataFormat(app.CreateDataProtector());

            #region Setup various static oauth options
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions
            {
                AccessTokenProvider = new AuthenticationTokenProvider()
                {
                    OnCreate = context =>
                    {
                        context.SetToken(context.SerializeTicket());
                    },
                    OnReceive = context =>
                    {
                        context.DeserializeTicket(context.Token);
                        context.OwinContext.Environment["Properties"] = context.Ticket.Properties;
                    }
                },

            };

            var publicClientId = "ngAuthApp";
            OAuthServerOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(1),
                Provider = new SimpleAuthorizationServerProvider(publicClientId),
                RefreshTokenProvider = new SimpleRefreshTokenProvider(),
                Description = new AuthenticationDescription { }

            };

            OAuthServerOptions.Description.Properties.Add("PublicClientId", publicClientId);

            #endregion

            app.UseCors(CorsOptions.AllowAll);

            //use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Local Token Generation
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);
            // NOTE: The actual order is important. UseOAuthBearerAuthentication calls UseStageMarker(PipelineStage.Authenticate); 
            // to make it (and everything before it) run earlier in the ASP.NET pipeline

            app.UseOAuthAuthorizationServer(OAuthServerOptions);

            #region --- Google Login: ---
            //Configure Google External Login
            GoogleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "659454074090-vhh7va2nd2p9ffhahs5jq72tg7k4b277.apps.googleusercontent.com",
                ClientSecret = "Xgr-lpBU8W_r7PBEE-zqNJT1",
                Provider = new GoogleAuthProvider(),
                Scope = { @"https://www.googleapis.com/auth/userinfo.profile" }
               
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
                Provider = new EkeyAuthProvider
                {
                    OnAuthenticated = (context) =>
                    {
                        // All data from facebook in this object. 
                        var rawUserObjectFromFacebookAsJson = context.User;

                        // Only some of the basic details from facebook 
                        // like id, username, email etc are added as claims.
                        // But you can retrieve any other details from this
                        // raw Json object from facebook and add it as claims here.
                        // Subsequently adding a claim here will also send this claim
                        // as part of the cookie set on the browser so you can retrieve
                        // on every successive request. 

                        // NOTE: The ExternalAccessToken is typically added to the context within the providers "Authenticated"-method: 
                        //context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));

                        return Task.FromResult(0);
                    }
                }
                
            };
            app.UseEkeyAuthentication(EkeyAuthOptions);


        }

    }

}