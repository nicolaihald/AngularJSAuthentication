using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace AngularJSAuthentication.EkeyAuth.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EkeyAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EkeyAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="subscriptions"></param>
        /// <param name="accessToken">Ekey Access token</param>
        public EkeyAuthenticatedContext(IOwinContext context, JObject user, JObject subscriptions, string accessToken)
            : base(context)
        {
            User = user;
            Subscriptions = subscriptions;
            AccessToken = accessToken;

            var productsToken = subscriptions.SelectToken("Products");
            if (productsToken != null)
            {
                var products = (from token in productsToken.Children()
                                //select new { ProductId = token["ProductId"], Provider = token["ProviderName"] }
                                select string.Format("{0}:{1}", token["ProductId"], token["ProviderName"])
                                ).ToList();

                Products = String.Join(",", products);

            }
            
            var userToken = user.SelectToken("UserLoggedInInfo");
            if (userToken != null)
            {
                var userInfo = userToken.FirstOrDefault();
                if (userInfo != null)
                {
                    UserId   = userInfo.Value<string>("UserIdentifier");
                    UserName = userInfo.Value<string>("UserIdentifier");
                    Email    = userInfo.Value<string>("UserIdentifier");
                }
            }
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// TODO::: Contains the Google user obtained from the endpoint https://www.googleapis.com/oauth2/v3/userinfo
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the JSON-serialized person
        /// </summary>
        /// <remarks>
        /// TODO::: Contains the Google+ person obtained from the endpoint https://www.googleapis.com/plus/v1/people/me.  For more information
        /// see https://developers.google.com/+/api/latest/people
        /// </remarks>
        public JObject Subscriptions { get; private set; }

        public string Products { get; private set; }

        /// <summary>
        /// Gets the Ekey access token
        /// </summary>
        public string AccessToken { get; private set; }


        /// <summary>
        /// Gets the Ekey user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Ekey username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Ekey email address for the account
        /// </summary>
        public string Email { get; private set; }


        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}