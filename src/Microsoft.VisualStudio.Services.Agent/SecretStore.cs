using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.VisualStudio.Services.Agent.Util;
using Newtonsoft.Json;
using System.IO;
using System.Runtime.Serialization;

namespace Microsoft.VisualStudio.Services.Agent
{
#if OS_WINDOWS
    [ServiceLocator(Default = typeof(WindowsAgentCredentialStore))]
#elif OS_OSX
    [ServiceLocator(Default = typeof(MacOSAgentCredentialStore))]
#else
    [ServiceLocator(Default = typeof(LinuxAgentCredentialStore))]
#endif
    public interface IAgentCredentialStore : IAgentService
    {
        NetworkCredential Write(string target, string username, string password);
        NetworkCredential Read(string target);
        void Delete(string target);
    }

#if OS_WINDOWS
    public sealed class WindowsAgentCredentialStore : AgentService, IAgentCredentialStore
    {
        public NetworkCredential Write(string target, string username, string password)
        {
            Trace.Entering();
            ArgUtil.NotNullOrEmpty(target, nameof(target));
            ArgUtil.NotNullOrEmpty(username, nameof(username));
            ArgUtil.NotNullOrEmpty(password, nameof(password));

            Credential credential = new Credential()
            {
                Type = CredentialType.Generic,
                Persist = (UInt32)CredentialPersist.LocalMachine,
                TargetName = Marshal.StringToCoTaskMemUni(target),
                UserName = Marshal.StringToCoTaskMemUni(username),
                CredentialBlob = Marshal.StringToCoTaskMemUni(password),
                CredentialBlobSize = (UInt32)Encoding.Unicode.GetByteCount(password),
                AttributeCount = 0,
                Comment = IntPtr.Zero,
                Attributes = IntPtr.Zero,
                TargetAlias = IntPtr.Zero
            };

            try
            {
                if (CredWrite(ref credential, 0))
                {
                    Trace.Info($"credentials for '{target}' written to store.");
                    return new NetworkCredential(username, password);
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, "Failed to write credentials");
                }
            }
            finally
            {
                if (credential.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(credential.CredentialBlob);
                }
                if (credential.TargetName != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(credential.TargetName);
                }
                if (credential.UserName != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(credential.UserName);
                }
            }
        }

        public NetworkCredential Read(string target)
        {
            Trace.Entering();
            IntPtr credPtr = IntPtr.Zero;
            try
            {
                if (CredRead(target, CredentialType.Generic, 0, out credPtr))
                {
                    Credential credStruct = (Credential)Marshal.PtrToStructure(credPtr, typeof(Credential));
                    int passwordLength = (int)credStruct.CredentialBlobSize;
                    string password = passwordLength > 0 ? Marshal.PtrToStringUni(credStruct.CredentialBlob, passwordLength / sizeof(char)) : String.Empty;
                    string username = Marshal.PtrToStringUni(credStruct.UserName);
                    Trace.Info($"Credentials for '{target}' read from store.");
                    return new NetworkCredential(username, password);
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error, $"CredRead throw an error for '{target}'");
                }
            }
            catch (Exception ex)
            {
                Trace.Error(ex);
                return null;
            }
            finally
            {
                if (credPtr != IntPtr.Zero)
                {
                    CredFree(credPtr);
                }
            }
        }

        public void Delete(string targetName)
        {
            try
            {
                if (!CredDelete(targetName, CredentialType.Generic, 0))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error > 0)
                    {
                        throw new Win32Exception(error, $"Failed to delete credentials for {targetName}");
                    }
                }
                else
                {
                    Trace.Info($"Credentials for '{targetName}' deleted from store.");
                }
            }
            catch (Exception exception)
            {
                Trace.Error(exception);
            }
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredDelete(string target, CredentialType type, int reservedFlag);

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr CredentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CredWrite([In] ref Credential userCredential, [In] UInt32 flags);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern bool CredFree([In] IntPtr cred);

        internal enum CredentialPersist : UInt32
        {
            Session = 0x01,
            LocalMachine = 0x02
        }

        internal enum CredentialType : uint
        {
            Generic = 0x01,
            DomainPassword = 0x02,
            DomainCertificate = 0x03
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct Credential
        {
            public UInt32 Flags;
            public CredentialType Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }
    }
#elif OS_OSX
    public sealed class MacOSAgentCredentialStore : AgentService, IAgentCredentialStore
    {
        public NetworkCredential Write(string target, string username, string password)
        {
            Trace.Entering();
            ArgUtil.NotNullOrEmpty(target, nameof(target));
            ArgUtil.NotNullOrEmpty(username, nameof(username));
            ArgUtil.NotNullOrEmpty(password, nameof(password));

            var whichUtil = HostContext.GetService<IWhichUtil>();
            string securityUtil = whichUtil.Which("security", true);

            List<string> securityOut = new List<string>();
            List<string> securityError = new List<string>();
            object outputLock = new object();
            using (var p = HostContext.CreateService<IProcessInvoker>())
            {
                p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                {
                    if (!string.IsNullOrEmpty(stdout.Data))
                    {
                        lock (outputLock)
                        {
                            securityOut.Add(stdout.Data);
                        }
                    }
                };

                p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                {
                    if (!string.IsNullOrEmpty(stderr.Data))
                    {
                        lock (outputLock)
                        {
                            securityError.Add(stderr.Data);
                        }
                    }
                };

                string agentBinary = Path.Combine(IOUtil.GetBinPath(), $"Agent.Listener{IOUtil.ExeExtension}");
                string workerBinary = Path.Combine(IOUtil.GetBinPath(), $"Agent.Worker{IOUtil.ExeExtension}");
                int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                              fileName: securityUtil,
                                              arguments: $"add-generic-password -s {target} -a username -w {username} -T \"{agentBinary}\" -T \"{workerBinary}\"",
                                              environment: null,
                                              cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                if (exitCode == 0)
                {
                    Trace.Info($"Successfully add-generic-password for {target} ({username})");
                }
                else
                {
                    if (securityOut.Count > 0)
                    {
                        Trace.Error(string.Join(Environment.NewLine, securityOut));
                    }
                    if (securityError.Count > 0)
                    {
                        Trace.Error(string.Join(Environment.NewLine, securityError));
                    }

                    throw new InvalidOperationException($"'security add-generic-password' failed with exit code {exitCode}.");
                }
            }

            securityOut.Clear();
            securityError.Clear();
            using (var p = HostContext.CreateService<IProcessInvoker>())
            {
                p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                {
                    if (!string.IsNullOrEmpty(stdout.Data))
                    {
                        lock (outputLock)
                        {
                            securityOut.Add(stdout.Data);
                        }
                    }
                };

                p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                {
                    if (!string.IsNullOrEmpty(stderr.Data))
                    {
                        lock (outputLock)
                        {
                            securityError.Add(stderr.Data);
                        }
                    }
                };

                string agentBinary = Path.Combine(IOUtil.GetBinPath(), $"Agent.Listener{IOUtil.ExeExtension}");
                string workerBinary = Path.Combine(IOUtil.GetBinPath(), $"Agent.Worker{IOUtil.ExeExtension}");
                int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                              fileName: securityUtil,
                                              arguments: $"add-generic-password -s {target} -a password -w {password} -T \"{agentBinary}\" -T \"{workerBinary}\"",
                                              environment: null,
                                              cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                if (exitCode == 0)
                {
                    Trace.Info($"Successfully add-generic-password for {target} ({password})");
                }
                else
                {
                    if (securityOut.Count > 0)
                    {
                        Trace.Error(string.Join(Environment.NewLine, securityOut));
                    }
                    if (securityError.Count > 0)
                    {
                        Trace.Error(string.Join(Environment.NewLine, securityError));
                    }

                    throw new InvalidOperationException($"'security add-generic-password' failed with exit code {exitCode}.");
                }
            }

            return new NetworkCredential(username, password);
        }

        public NetworkCredential Read(string target)
        {
            Trace.Entering();
            ArgUtil.NotNullOrEmpty(target, nameof(target));
            string username;
            string password;
            try
            {
                var whichUtil = HostContext.GetService<IWhichUtil>();
                string securityUtil = whichUtil.Which("security", true);

                List<string> securityOut = new List<string>();
                List<string> securityError = new List<string>();
                object outputLock = new object();
                using (var p = HostContext.CreateService<IProcessInvoker>())
                {
                    p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                    {
                        if (!string.IsNullOrEmpty(stdout.Data))
                        {
                            lock (outputLock)
                            {
                                securityOut.Add(stdout.Data);
                            }
                        }
                    };

                    p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                    {
                        if (!string.IsNullOrEmpty(stderr.Data))
                        {
                            lock (outputLock)
                            {
                                securityError.Add(stderr.Data);
                            }
                        }
                    };

                    int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                                  fileName: securityUtil,
                                                  arguments: $"find-generic-password -s {target} -a username -w -g",
                                                  environment: null,
                                                  cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                    if (exitCode == 0)
                    {
                        username = securityOut.First();
                        Trace.Info($"Successfully find-generic-password for {target} (username)");
                    }
                    else
                    {
                        if (securityOut.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityOut));
                        }
                        if (securityError.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityError));
                        }

                        throw new InvalidOperationException($"'security find-generic-password' failed with exit code {exitCode}.");
                    }
                }

                securityOut.Clear();
                securityError.Clear();
                using (var p = HostContext.CreateService<IProcessInvoker>())
                {
                    p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                    {
                        if (!string.IsNullOrEmpty(stdout.Data))
                        {
                            lock (outputLock)
                            {
                                securityOut.Add(stdout.Data);
                            }
                        }
                    };

                    p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                    {
                        if (!string.IsNullOrEmpty(stderr.Data))
                        {
                            lock (outputLock)
                            {
                                securityError.Add(stderr.Data);
                            }
                        }
                    };

                    int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                                  fileName: securityUtil,
                                                  arguments: $"find-generic-password -s {target} -a password -w -g",
                                                  environment: null,
                                                  cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                    if (exitCode == 0)
                    {
                        password = securityOut.First();
                        Trace.Info($"Successfully find-generic-password for {target} (password)");
                    }
                    else
                    {
                        if (securityOut.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityOut));
                        }
                        if (securityError.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityError));
                        }

                        throw new InvalidOperationException($"'security add-generic-password' failed with exit code {exitCode}.");
                    }
                }

                return new NetworkCredential(username, password);
            }
            catch (Exception ex)
            {
                Trace.Error(ex);
                return null;
            }
        }
        public void Delete(string target)
        {
            Trace.Entering();
            ArgUtil.NotNullOrEmpty(target, nameof(target));

            var whichUtil = HostContext.GetService<IWhichUtil>();
            string securityUtil = whichUtil.Which("security");
            if (string.IsNullOrEmpty(securityUtil))
            {
                return;
            }

            List<string> securityOut = new List<string>();
            List<string> securityError = new List<string>();
            object outputLock = new object();
            try
            {
                using (var p = HostContext.CreateService<IProcessInvoker>())
                {
                    p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                    {
                        if (!string.IsNullOrEmpty(stdout.Data))
                        {
                            lock (outputLock)
                            {
                                securityOut.Add(stdout.Data);
                            }
                        }
                    };

                    p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                    {
                        if (!string.IsNullOrEmpty(stderr.Data))
                        {
                            lock (outputLock)
                            {
                                securityError.Add(stderr.Data);
                            }
                        }
                    };

                    int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                                  fileName: securityUtil,
                                                  arguments: $"delete-generic-password -s {target} -a username",
                                                  environment: null,
                                                  cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                    if (exitCode == 0)
                    {
                        Trace.Info($"Successfully delete-generic-password for {target} (username)");
                    }
                    else
                    {
                        if (securityOut.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityOut));
                        }
                        if (securityError.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityError));
                        }

                        throw new InvalidOperationException($"'security delete-generic-password' failed with exit code {exitCode}.");
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.Error(ex);
            }

            securityOut.Clear();
            securityError.Clear();

            try
            {
                using (var p = HostContext.CreateService<IProcessInvoker>())
                {
                    p.OutputDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stdout)
                    {
                        if (!string.IsNullOrEmpty(stdout.Data))
                        {
                            lock (outputLock)
                            {
                                securityOut.Add(stdout.Data);
                            }
                        }
                    };

                    p.ErrorDataReceived += delegate (object sender, ProcessDataReceivedEventArgs stderr)
                    {
                        if (!string.IsNullOrEmpty(stderr.Data))
                        {
                            lock (outputLock)
                            {
                                securityError.Add(stderr.Data);
                            }
                        }
                    };

                    int exitCode = p.ExecuteAsync(workingDirectory: IOUtil.GetRootPath(),
                                                  fileName: securityUtil,
                                                  arguments: $"delete-generic-password -s {target} -a password",
                                                  environment: null,
                                                  cancellationToken: CancellationToken.None).GetAwaiter().GetResult();
                    if (exitCode == 0)
                    {
                        Trace.Info($"Successfully delete-generic-password for {target} (password)");
                    }
                    else
                    {
                        if (securityOut.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityOut));
                        }
                        if (securityError.Count > 0)
                        {
                            Trace.Error(string.Join(Environment.NewLine, securityError));
                        }

                        throw new InvalidOperationException($"'security delete-generic-password' failed with exit code {exitCode}.");
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.Error(ex);
            }
        }
    }
#else
    public sealed class LinuxAgentCredentialStore : AgentService, IAgentCredentialStore
    {
        private string _credStoreFile;
        private Dictionary<string, Credential> _credStore;

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);

            _credStoreFile = IOUtil.GetAgentCredStoreFilePath();
            if (!File.Exists(_credStoreFile))
            {
                _credStore = new Dictionary<string, Credential>();
                IOUtil.SaveObject(_credStore, _credStoreFile);

                // Try to lock down the .credentials_store file to the owner/group
                var whichUtil = hostContext.GetService<IWhichUtil>();
                var chmodPath = whichUtil.Which("chmod");
                if (!String.IsNullOrEmpty(chmodPath))
                {
                    var arguments = $"600 {new FileInfo(_credStoreFile).FullName}";
                    using (var invoker = hostContext.CreateService<IProcessInvoker>())
                    {
                        var exitCode = invoker.ExecuteAsync(IOUtil.GetRootPath(), chmodPath, arguments, null, default(CancellationToken)).GetAwaiter().GetResult();
                        if (exitCode == 0)
                        {
                            Trace.Info("Successfully set permissions for credentials store file {0}", _credStoreFile);
                        }
                        else
                        {
                            Trace.Warning("Unable to successfully set permissions for credentials store file {0}. Received exit code {1} from {2}", _credStoreFile, exitCode, chmodPath);
                        }
                    }
                }
                else
                {
                    Trace.Warning("Unable to locate chmod to set permissions for credentials store file {0}.", _credStoreFile);
                }
            }
            else
            {
                _credStore = IOUtil.LoadObject<Dictionary<string, Credential>>(_credStoreFile);
                foreach (var cred in _credStore)
                {
                    cred.Value.Password = Decrypt(cred.Value.Password);
                }
            }
        }

        public NetworkCredential Write(string target, string username, string password)
        {
            Trace.Entering();
            ArgUtil.NotNullOrEmpty(target, nameof(target));
            ArgUtil.NotNullOrEmpty(username, nameof(username));
            ArgUtil.NotNullOrEmpty(password, nameof(password));

            Credential cred = new Credential(username, password);
            _credStore[target] = cred;
            UpdateCredentialStore();

            return new NetworkCredential(username, password);
        }

        public NetworkCredential Read(string target)
        {
            if (!string.IsNullOrEmpty(target) && _credStore.ContainsKey(target))
            {
                Credential cred = _credStore[target];
                if (!string.IsNullOrEmpty(cred.UserName) && !string.IsNullOrEmpty(cred.Password))
                {
                    return new NetworkCredential(cred.UserName, cred.Password);
                }
            }

            return null;
        }

        public void Delete(string target)
        {
            if (_credStore.ContainsKey(target))
            {
                _credStore.Remove(target);
                UpdateCredentialStore();
            }
        }

        private void UpdateCredentialStore()
        {
            foreach (var cred in _credStore)
            {
                cred.Value.Password = Encrypt(cred.Value.Password);
            }

            IOUtil.SaveObject(_credStore, _credStoreFile);
        }

        private string Encrypt(string secret)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(secret));
        }

        private string Decrypt(string encryptedText)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(encryptedText));
        }
    }

    [DataContract]
    internal class Credential
    {
        public Credential()
        { }

        public Credential(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        [DataMember(IsRequired = true)]
        public string UserName { get; set; }

        [DataMember(IsRequired = true)]
        public string Password { get; set; }
    }
#endif
}
