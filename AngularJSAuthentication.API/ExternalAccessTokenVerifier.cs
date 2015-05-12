using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using AngularJSAuthentication.API.Models;
using Newtonsoft.Json.Linq;

namespace AngularJSAuthentication.API
{
    public static class ExternalAccessTokenVerifier
    {
        public static async Task<ParsedExternalAccessToken> VerifyToken(string provider, string accessToken)
        {
            ParsedExternalAccessToken parsedToken = null;
            var client = new HttpClient();

            var verifyTokenEndPoint = "";

            if (provider == "Facebook")
            {
                //You can get it from here: https://developers.facebook.com/tools/accesstoken/
                //More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
                var appToken = "xxxxxx";
                verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", accessToken, appToken);
            }
            else if (provider == "Google")
            {
                verifyTokenEndPoint = string.Format("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={0}", accessToken);
            }
            else if (provider == "Ekey")
            {
                verifyTokenEndPoint =
                    string.Format("https://test-loginconnector.gyldendal.dk/api/LoggedInfo/GetAuthInfo"); //"?access_token={0}", accessToken);

                // TEMP HACK:
                var requestData = (dynamic)new JObject();
                requestData.subscriptionAuthentToken = accessToken;
                requestData.clientWebShopName = Startup.EkeyAuthOptions.AppId;
                requestData.SharedSecret = Startup.EkeyAuthOptions.AppSecret;

                var loggedInfoRequest = new HttpRequestMessage(HttpMethod.Post, verifyTokenEndPoint);
                loggedInfoRequest.Content = new StringContent(requestData.ToString(), Encoding.UTF8, "application/json");

                loggedInfoRequest.Headers.Add("User-Agent", "OWIN Ekey OAuth Provider");
                loggedInfoRequest.Headers.Add("LOGINCONNECTORAPIKEY", Startup.EkeyAuthOptions.ConnectorApiKey);

                HttpResponseMessage loggedInfoResponse = await client.SendAsync(loggedInfoRequest);
                loggedInfoResponse.EnsureSuccessStatusCode();
                var text = await loggedInfoResponse.Content.ReadAsStringAsync();

                JObject user = JObject.Parse(text);
                JToken userInfo = user["UserLoggedInInfo"][0];

                if (userInfo != null)
                {
                    var notValidatedToken = new ParsedExternalAccessToken();

                    notValidatedToken.user_id = userInfo.Value<string>("UserIdentifier");
                    notValidatedToken.app_id = Startup.EkeyAuthOptions.AppId;

                    return notValidatedToken;
                }
            }
            else
            {
                return null;
            }


            var uri = new Uri(verifyTokenEndPoint);
            var response = await client.GetAsync(uri);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                dynamic jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);

                parsedToken = new ParsedExternalAccessToken();

                if (provider == "Facebook")
                {
                    parsedToken.user_id = jObj["data"]["user_id"];
                    parsedToken.app_id = jObj["data"]["app_id"];

                    if (!string.Equals(Startup.FacebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }
                }
                else if (provider == "Google")
                {
                    parsedToken.user_id = jObj["user_id"];
                    parsedToken.app_id = jObj["audience"];

                    if (!string.Equals(Startup.GoogleAuthOptions.ClientId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                }

                if (provider == "Ekey")
                {
                    parsedToken.user_id = jObj["UserLoggedInInfo"]["UserIdentifier"];
                    parsedToken.app_id = jObj["UserLoggedInInfo"]["LoginProvider"];
                    //parsedToken.app_id = jObj["UserLoggedInInfo"]["app_id"];

                    if (!string.Equals(Startup.FacebookAuthOptions.AppId, parsedToken.app_id, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }
                }

            }

            return parsedToken;
        }
    }
}