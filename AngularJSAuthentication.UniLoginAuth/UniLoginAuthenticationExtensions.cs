using Owin;

namespace AngularJSAuthentication.UniLoginAuth
{
    public static class UniLoginAuthenticationExtensions
    {
        public static IAppBuilder UseUniLoginAuthentication(this IAppBuilder app, UniLoginAuthenticationOptions options)
        {
            return app.Use(typeof(UniLoginAuthenticationMiddleware), app, options);
        }
    }
}