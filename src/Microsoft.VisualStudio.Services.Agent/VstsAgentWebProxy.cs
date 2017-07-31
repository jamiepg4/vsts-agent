using Microsoft.VisualStudio.Services.Agent.Util;
using System;
using System.Linq;
using System.Net;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
#if OS_WINDOWS
using System.Security.Cryptography;
#endif

namespace Microsoft.VisualStudio.Services.Agent
{
    [DataContract]
    internal class ProxyCredential
    {
        internal ProxyCredential()
        { }

        internal ProxyCredential(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        [DataMember]
        public string UserName { get; set; }

        [DataMember]
        public string Password { get; set; }
    }

    [ServiceLocator(Default = typeof(VstsAgentWebProxy))]
    public interface IVstsAgentWebProxy : IAgentService, IWebProxy
    {
        string ProxyAddress { get; }
        string ProxyUsername { get; }
        string ProxyPassword { get; }
        List<string> ProxyBypassList { get; }
    }

    public class VstsAgentWebProxy : AgentService, IVstsAgentWebProxy, IWebProxy
    {
        private readonly List<Regex> _regExBypassList = new List<Regex>();
        private readonly List<string> _bypassList = new List<string>();

        public string ProxyAddress { get; private set; }
        public string ProxyUsername { get; private set; }
        public string ProxyPassword { get; private set; }
        public List<string> ProxyBypassList => _bypassList;

        public ICredentials Credentials { get; set; }

        public override void Initialize(IHostContext context)
        {
            base.Initialize(context);
            LoadProxySetting();
        }

        public Uri GetProxy(Uri destination)
        {
            if (IsBypassed(destination))
            {
                return destination;
            }
            else
            {
                return new Uri(ProxyAddress);
            }
        }

        public bool IsBypassed(Uri uri)
        {
            return string.IsNullOrEmpty(ProxyAddress) || uri.IsLoopback || IsMatchInBypassList(uri);
        }

        public void SetupProxy(string proxyAddress, string proxyUsername, string proxyPassword)
        {
            ArgUtil.NotNullOrEmpty(proxyAddress, nameof(proxyAddress));
            ProxyAddress = proxyAddress;
            ProxyUsername = proxyUsername;
            ProxyPassword = proxyPassword;

            if (string.IsNullOrEmpty(ProxyUsername) || string.IsNullOrEmpty(ProxyPassword))
            {
                Credentials = CredentialCache.DefaultNetworkCredentials;
            }
            else
            {
                Credentials = new NetworkCredential(ProxyUsername, ProxyPassword);
            }
        }

        public void SaveProxySetting()
        {
            if (!string.IsNullOrEmpty(ProxyAddress))
            {
                string proxyConfigFile = IOUtil.GetProxyConfigFilePath();
                IOUtil.DeleteFile(proxyConfigFile);
                Trace.Info($"Store proxy configuration to '{proxyConfigFile}' for proxy '{ProxyAddress}'");
                File.WriteAllText(proxyConfigFile, ProxyAddress);

                if (!string.IsNullOrEmpty(ProxyUsername) && !string.IsNullOrEmpty(ProxyPassword))
                {
                    ProxyCredential cred = new ProxyCredential(ProxyPassword, ProxyPassword);
                    SaveProxyCredential(cred);
                }
            }
            else
            {
                Trace.Info("No proxy configuration exist.");
            }
        }

        private void LoadProxySetting()
        {
            string proxyConfigFile = IOUtil.GetProxyConfigFilePath();
            if (File.Exists(proxyConfigFile))
            {
                // we expect the first line of the file is the proxy url
                Trace.Verbose($"Try read proxy setting from file: {proxyConfigFile}.");
                ProxyAddress = File.ReadLines(proxyConfigFile).FirstOrDefault() ?? string.Empty;
                ProxyAddress = ProxyAddress.Trim();
                Trace.Verbose($"{ProxyAddress}");
            }

            if (string.IsNullOrEmpty(ProxyAddress))
            {
                Trace.Verbose("Try read proxy setting from environment variable: 'VSTS_HTTP_PROXY'.");
                ProxyAddress = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY") ?? string.Empty;
                ProxyAddress = ProxyAddress.Trim();
                Trace.Verbose($"{ProxyAddress}");
            }

            if (!string.IsNullOrEmpty(ProxyAddress) && !Uri.IsWellFormedUriString(ProxyAddress, UriKind.Absolute))
            {
                Trace.Info($"The proxy url is not a well formed absolute uri string: {ProxyAddress}.");
                ProxyAddress = string.Empty;
            }

            if (!string.IsNullOrEmpty(ProxyAddress))
            {
                Trace.Info($"Config proxy at: {ProxyAddress}.");

                ProxyCredential proxyCred = ReadProxyCredential();
                if (proxyCred == null)
                {
                    ProxyUsername = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY_USERNAME");
                    ProxyPassword = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY_PASSWORD");
                }
                else
                {
                    ProxyUsername = proxyCred.UserName;
                    ProxyPassword = proxyCred.Password;
                }

                if (!string.IsNullOrEmpty(ProxyPassword))
                {
                    var secretMasker = HostContext.GetService<ISecretMasker>();
                    secretMasker.AddValue(ProxyPassword);
                }

                if (string.IsNullOrEmpty(ProxyUsername) || string.IsNullOrEmpty(ProxyPassword))
                {
                    Trace.Info($"Config proxy use DefaultNetworkCredentials.");
                    Credentials = CredentialCache.DefaultNetworkCredentials;
                }
                else
                {
                    Trace.Info($"Config authentication proxy as: {ProxyUsername}.");
                    Credentials = new NetworkCredential(ProxyUsername, ProxyPassword);
                }

                string proxyBypassFile = IOUtil.GetProxyBypassFilePath();
                if (File.Exists(proxyBypassFile))
                {
                    Trace.Verbose($"Try read proxy bypass list from file: {proxyBypassFile}.");
                    foreach (string bypass in File.ReadAllLines(proxyBypassFile))
                    {
                        if (string.IsNullOrWhiteSpace(bypass))
                        {
                            continue;
                        }
                        else
                        {
                            Trace.Info($"Bypass proxy for: {bypass}.");
                            try
                            {
                                Regex bypassRegex = new Regex(bypass.Trim(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.ECMAScript);
                                _regExBypassList.Add(bypassRegex);
                                ProxyBypassList.Add(bypass.Trim());
                            }
                            catch (Exception ex)
                            {
                                Trace.Error($"{bypass} is not a valid Regex, won't bypass proxy for {bypass}.");
                                Trace.Error(ex);
                            }
                        }
                    }
                }
            }
            else
            {
                Trace.Info($"No proxy setting found.");
            }
        }

        private bool IsMatchInBypassList(Uri input)
        {
            string matchUriString = input.IsDefaultPort ?
                input.Scheme + "://" + input.Host :
                input.Scheme + "://" + input.Host + ":" + input.Port.ToString();

            foreach (Regex r in _regExBypassList)
            {
                if (r.IsMatch(matchUriString))
                {
                    return true;
                }
            }

            return false;
        }

        private void SaveProxyCredential(ProxyCredential cred)
        {
            string proxyCredFile = IOUtil.GetProxyCredentialsFilePath();
            IOUtil.DeleteFile(proxyCredFile);

            var credString = StringUtil.ConvertToJson(cred);
#if OS_WINDOWS
            var encryptedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(credString), null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(proxyCredFile, encryptedBytes);
            File.SetAttributes(proxyCredFile, File.GetAttributes(proxyCredFile) | FileAttributes.Hidden);
#else
            // Now write the parameters to disk
            IOUtil.SaveObject(cred, proxyCredFile);
            Trace.Info("Successfully saved RSA key parameters to file {0}", proxyCredFile);

            // Try to lock down the credentials_key file to the owner/group
            var whichUtil = HostContext.GetService<IWhichUtil>();
            var chmodPath = whichUtil.Which("chmod");
            if (!String.IsNullOrEmpty(chmodPath))
            {
                var arguments = $"600 {new FileInfo(proxyCredFile).FullName}";
                using (var invoker = HostContext.CreateService<IProcessInvoker>())
                {
                    var exitCode = invoker.ExecuteAsync(IOUtil.GetRootPath(), chmodPath, arguments, null, default(CancellationToken)).GetAwaiter().GetResult();
                    if (exitCode == 0)
                    {
                        Trace.Info("Successfully set permissions for RSA key parameters file {0}", proxyCredFile);
                    }
                    else
                    {
                        Trace.Warning("Unable to successfully set permissions for RSA key parameters file {0}. Received exit code {1} from {2}", proxyCredFile, exitCode, chmodPath);
                    }
                }
            }
            else
            {
                Trace.Warning("Unable to locate chmod to set permissions for RSA key parameters file {0}.", proxyCredFile);
            }
#endif        
        }

        private ProxyCredential ReadProxyCredential()
        {
            string proxyCredFile = IOUtil.GetProxyCredentialsFilePath();
            if (File.Exists(proxyCredFile))
            {
#if OS_WINDOWS
                var encryptedBytes = File.ReadAllBytes(proxyCredFile);
                var credString = Encoding.UTF8.GetString(ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine));
                return StringUtil.ConvertFromJson<ProxyCredential>(credString);
#else
                return IOUtil.LoadObject<ProxyCredential>(proxyCredFile);
#endif   
            }
            else
            {
                return null;
            }
        }
    }
}
