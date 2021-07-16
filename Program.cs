using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OAuth1_No_Library_Helper
{
    class Program
    {
        // Fill in these 4 variables
        private static string conversationId = "";
        private static string consumerKey = "";
        private static string consumerSecret = "";
        private static string tokenValue = "";
        // You don't need to modify anything below this line

        private static string tokenSecret = ""; // Leave this an empty string
        private static string url = "https://staging-rest.call-em-all.com/v1/conversations/" + conversationId + "/textmessages";

        private static readonly string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };

        private static string EscapeUriDataStringRfc3986(string value)
        {

            StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(value));
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }
            return escaped.ToString();
        }
        static void Main(string[] args)
        {
            try
            {
                string Escape(string s)
                {
                    var charsToEscape = new[] { "!", "*", "'", "(", ")" };
                    var escaped = new StringBuilder(Uri.EscapeDataString(s));
                    foreach (var t in charsToEscape)
                    {
                        escaped.Replace(t, Uri.HexEscape(t[0]));
                    }
                    return escaped.ToString();
                }



                var httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
                httpWebRequest.Method = "GET";

                var timeStamp = ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
                var nonce = Convert.ToBase64String(Encoding.UTF8.GetBytes(timeStamp));

                var signatureBaseString = Escape(httpWebRequest.Method.ToUpper()) + "&";
                signatureBaseString += EscapeUriDataStringRfc3986(url.ToLower()) + "&";
                signatureBaseString += EscapeUriDataStringRfc3986(
                    "oauth_consumer_key=" + EscapeUriDataStringRfc3986(consumerKey) + "&" +
                    "oauth_nonce=" + EscapeUriDataStringRfc3986(nonce) + "&" +
                    "oauth_signature_method=" + EscapeUriDataStringRfc3986("HMAC-SHA1") + "&" +
                    "oauth_timestamp=" + EscapeUriDataStringRfc3986(timeStamp) + "&" +
                    "oauth_token=" + EscapeUriDataStringRfc3986(tokenValue) + "&" +
                    "oauth_version=" + EscapeUriDataStringRfc3986("1.0"));
                // Un-comment the line below to see how the signatureBaseString looks
                // Console.WriteLine(@"signatureBaseString: " + signatureBaseString);

                var key = EscapeUriDataStringRfc3986(consumerSecret) + "&" + EscapeUriDataStringRfc3986(tokenSecret);
                // Un-comment the line below to see how the key looks
                // Console.WriteLine(@"key: " + key);
                var signatureEncoding = new ASCIIEncoding();
                var keyBytes = signatureEncoding.GetBytes(key);
                var signatureBaseBytes = signatureEncoding.GetBytes(signatureBaseString);
                string signatureString;
                using (var hmacsha1 = new HMACSHA1(keyBytes))
                {
                    var hashBytes = hmacsha1.ComputeHash(signatureBaseBytes);
                    signatureString = Convert.ToBase64String(hashBytes);
                }
                signatureString = EscapeUriDataStringRfc3986(signatureString);
                // Un-comment the line below to see how the signatureString looks
                // Console.WriteLine(@"signatureString: " + signatureString);

                string SimpleQuote(string s) => '"' + s + '"';
                var header =
                    "OAuth realm=" + SimpleQuote("") + "," +
                    "oauth_consumer_key=" + SimpleQuote(consumerKey) + "," +
                    "oauth_nonce=" + SimpleQuote(nonce) + "," +
                    "oauth_signature_method=" + SimpleQuote("HMAC-SHA1") + "," +
                    "oauth_timestamp=" + SimpleQuote(timeStamp) + "," +
                    "oauth_token=" + SimpleQuote(tokenValue) + "," +
                    "oauth_version=" + SimpleQuote("1.0") + "," +
                    "oauth_signature= " + SimpleQuote(signatureString);
                // Un-comment the line below to see how the header looks
                // Console.WriteLine(@"header: " + header);
                httpWebRequest.Headers.Add(HttpRequestHeader.Authorization, header);

                var response = httpWebRequest.GetResponse();
                var characterSet = ((HttpWebResponse)response).CharacterSet;
                var responseEncoding = characterSet == ""
                    ? Encoding.UTF8
                    : Encoding.GetEncoding(characterSet ?? "utf-8");
                var responsestream = response.GetResponseStream();
                if (responsestream == null)
                {
                    throw new ArgumentNullException(nameof(characterSet));
                }
                using (responsestream)
                {
                    var reader = new StreamReader(responsestream, responseEncoding);
                    var result = reader.ReadToEnd();
                    Console.WriteLine(@"result: " + result);
                    Console.ReadLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(@"Error: " + e);
                Console.ReadLine();
            }
        }
    }
}
