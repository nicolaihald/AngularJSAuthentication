using Owin;

namespace AngularJSAuthentication.EkeyAuth
{
    public static class EkeyAuthenticationExtensions
    {
        public static IAppBuilder UseEkeyAuthentication(this IAppBuilder app, EkeyAuthenticationOptions options)
        {
            return app.Use(typeof(EkeyAuthenticationMiddleware), app, options);
        }
    }
}