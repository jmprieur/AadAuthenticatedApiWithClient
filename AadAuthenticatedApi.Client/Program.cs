using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using System;
using System.IO;
using System.Threading.Tasks;

namespace AadAuthenticatedApi.Client
{
    class Program
    {
        internal IPublicClientApplication MsalClient;
        internal string[] Scopes;
        internal IAccount UserAccount;
        internal string AppId;

        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting authentication");

            var appConfig = LoadAppSettings();

            if (appConfig == null)
            {
                Console.WriteLine("Missing or invalid appsettings.json...exiting");
                return;
            }

            var p = new Program
            {
                Scopes = appConfig.GetSection("scopes").Get<string[]>(),
                AppId = appConfig["appId"]
            };

            var result = await p.GetAccessToken();
            File.WriteAllText("foo.txt", result);

            Console.WriteLine(result);

            Console.ReadLine();
        }

        public async Task<string> GetAccessToken()
        {
            MsalClient = PublicClientApplicationBuilder
                    .Create(AppId)
                    .WithTenantId("organizations")
                    .Build();

            // If there is no saved user account, the user must sign-in
            if (UserAccount == null)
            {
                try
                {
                    // Invoke device code flow so user can sign-in with a browser
                    var result = await MsalClient.AcquireTokenWithDeviceCode(Scopes, callback => {
                        Console.WriteLine(callback.Message);
                        return Task.FromResult(0);
                    }).ExecuteAsync();

                    UserAccount = result.Account;
                    return result.AccessToken;
                }
                catch (Exception exception)
                {
                    Console.WriteLine($"Error getting access token: {exception.Message}");
                    return null;
                }
            }
            else
            {
                var result = await MsalClient
                    .AcquireTokenSilent(Scopes, UserAccount)
                    .ExecuteAsync();

                return result.AccessToken;
            }
        }

        static IConfigurationRoot LoadAppSettings()
        {
            var appConfig = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", false, true)
                .Build();

            // Check for required settings
            if (string.IsNullOrEmpty(appConfig["appId"]) ||
                // Make sure there's at least one value in the scopes array
                string.IsNullOrEmpty(appConfig["scopes:0"]))
            {
                return null;
            }

            return appConfig;
        }
    }
}
