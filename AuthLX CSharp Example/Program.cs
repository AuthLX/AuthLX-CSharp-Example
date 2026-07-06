using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using AuthLX;

namespace AuthLX_CSharp_Example
{
    internal class Program
    {
        public static api AuthLXApp = new api(
    name: "internal", 
    ownerid: "2ec0f300-440e-4ee1-b23d-417b7da88f8e",
    secret: "3b147f4218ea765e4e3496efd3ffdbf1046c81909813df0786e642e8d2a39ed5",
    version: "1.0"
);

        private static void ClearConsole()
        {
            Console.Clear();
        }

        private static string GetInput(string prompt)
        {
            Console.Write(prompt);
            string val = Console.ReadLine();
            return val != null ? val.Trim() : "";
        }

        private static void ShowBanner(api authlxapp)
        {
            ClearConsole();
            string mode = string.IsNullOrEmpty(authlxapp.client_secret) ? "OFF ⚠" : "SECURE 🔒";
            Console.WriteLine("╔" + new string('=', 58) + "╗");

            string title = "║  " + authlxapp.name + "  —  Powered by AuthLX";
            if (title.Length < 60)
            {
                title += new string(' ', 60 - title.Length);
            }
            title += "║";
            Console.WriteLine(title);

            string modeLine = "║  Anti-Tamper: " + mode;
            if (modeLine.Length < 60)
            {
                modeLine += new string(' ', 60 - modeLine.Length);
            }
            modeLine += "║";
            Console.WriteLine(modeLine);

            Console.WriteLine("╚" + new string('=', 58) + "╝");

            if (authlxapp.user_data.is_authenticated && !string.IsNullOrEmpty(authlxapp.user_data.username))
            {
                Console.WriteLine($"\n  Logged in as: {authlxapp.user_data.username}");
            }
        }

        private static string ShowMainMenu()
        {
            Console.WriteLine("\n  MAIN MENU");
            Console.WriteLine("  " + new string('-', 53));
            Console.WriteLine("  [1]  Login");
            Console.WriteLine("  [2]  Register with License Key");
            Console.WriteLine("  [3]  Web Login  (no HWID)");
            Console.WriteLine("  [4]  Web Register  (no HWID)");
            Console.WriteLine("  [5]  Forgot Password  (HWID-verified reset)");
            Console.WriteLine("  [6]  Verify Standalone API Token");
            Console.WriteLine("  [7]  Show HWID methods");
            Console.WriteLine("  [8]  Debug Info");
            Console.WriteLine("  [0]  Exit");
            return GetInput("\n  › ");
        }

        private static string ShowAccountMenu()
        {
            Console.WriteLine("\n  ACCOUNT MENU");
            Console.WriteLine("  " + new string('-', 53));
            Console.WriteLine("  [1]  Account Details  (view info & expiry)");
            Console.WriteLine("  [2]  Change Username");
            Console.WriteLine("  [3]  Upgrade Account  (apply another license key)");
            Console.WriteLine("  [4]  Verify Session");
            Console.WriteLine("  [5]  Logout");
            Console.WriteLine("  [0]  Back");
            return GetInput("\n  › ");
        }

        private static bool ExampleLogin(api authlxapp)
        {
            Console.WriteLine("\n── LOGIN ──────────────────────────────────────────────");
            string user = GetInput("  Username : ");
            string password = GetInput("  Password : ");

            if (authlxapp.login(user, password))
            {
                Console.WriteLine($"\n  ✓ Logged in as '{authlxapp.user_data.username}'");
                Console.WriteLine($"  Subscription : {(string.IsNullOrEmpty(authlxapp.user_data.subscription) ? "N/A" : authlxapp.user_data.subscription)}");
                Console.WriteLine($"  Expires      : {(string.IsNullOrEmpty(authlxapp.user_data.expires) ? "N/A" : authlxapp.user_data.expires)}");
                Console.WriteLine($"  Last Login   : {(string.IsNullOrEmpty(authlxapp.user_data.lastlogin) ? "N/A" : authlxapp.user_data.lastlogin)}");

                double remaining = authlxapp.expiry_remaining();
                if (remaining > 0.0)
                {
                    int d = (int)(remaining / 86400.0);
                    int h = (int)((remaining % 86400.0) / 3600.0);
                    Console.WriteLine($"  Time left    : {d}d {h}h");
                }
                else
                {
                    Console.WriteLine("  Time left    : EXPIRED");
                }

                authlxapp.start_ban_monitor(120);
                Console.WriteLine("  Ban monitor  : Active (120s interval)");
                return true;
            }

            Console.WriteLine("  ✗ Login failed.");
            return false;
        }

        private static void ExampleRegister(api authlxapp)
        {
            Console.WriteLine("\n── REGISTER ────────────────────────────────────────────");
            string user = GetInput("  Username    : ");
            string email = GetInput("  Email       : ");
            string password = GetInput("  Password    : ");
            string key = GetInput("  License Key : ");

            if (authlxapp.registerAccount(user, email, password, key))
            {
                Console.WriteLine("  ✓ Registered! You can now log in.");
            }
            else
            {
                Console.WriteLine("  ✗ Registration failed. Check the license key.");
            }
        }

        private static bool ExampleWebLogin(api authlxapp)
        {
            Console.WriteLine("\n── WEB LOGIN (no HWID) ─────────────────────────────────");
            string user = GetInput("  Username : ");
            string password = GetInput("  Password : ");

            if (authlxapp.webLogin(user, password))
            {
                Console.WriteLine($"\n  ✓ Authenticated as '{authlxapp.user_data.username}'");
                Console.WriteLine($"  Subscription : {(string.IsNullOrEmpty(authlxapp.user_data.subscription) ? "N/A" : authlxapp.user_data.subscription)}");
                Console.WriteLine($"  Expires      : {(string.IsNullOrEmpty(authlxapp.user_data.expires) ? "N/A" : authlxapp.user_data.expires)}");
                Console.WriteLine($"  Last Login   : {(string.IsNullOrEmpty(authlxapp.user_data.lastlogin) ? "N/A" : authlxapp.user_data.lastlogin)}");

                authlxapp.start_ban_monitor(120);
                Console.WriteLine("  Ban monitor  : Active (120s interval)");
                return true;
            }
            else
            {
                if (authlxapp.lockout_active())
                {
                    long secs = authlxapp.lockout_remaining_ms() / 1000;
                    Console.WriteLine($"  ✗ Locked out for {secs} seconds.");
                }
                else
                {
                    Console.WriteLine("  ✗ Web login failed.");
                }
                return false;
            }
        }

        private static void ExampleRegisterWeb(api authlxapp)
        {
            Console.WriteLine("\n── WEB REGISTER (no HWID) ──────────────────────────────");
            string user = GetInput("  Username    : ");
            string email = GetInput("  Email       : ");
            string password = GetInput("  Password    : ");
            string key = GetInput("  License Key : ");

            if (authlxapp.registerWeb(user, email, password, key))
            {
                Console.WriteLine("  ✓ Registered via web flow!");
            }
            else
            {
                Console.WriteLine("  ✗ Registration failed.");
            }
        }

        private static void ExampleUpgrade(api authlxapp)
        {
            Console.WriteLine("\n── UPGRADE ACCOUNT ─────────────────────────────────────");
            string user = GetInput("  Username    : ");
            if (string.IsNullOrEmpty(user))
            {
                user = authlxapp.user_data.username;
            }
            string key = GetInput("  License Key : ");

            if (authlxapp.upgrade(user, key))
            {
                Console.WriteLine("  ✓ Account upgraded!");
            }
            else
            {
                Console.WriteLine("  ✗ Upgrade failed. Check the license key.");
            }
        }

        private static void ExampleChangeUsername(api authlxapp)
        {
            Console.WriteLine("\n── CHANGE USERNAME ─────────────────────────────────────");
            string newName = GetInput("  New Username : ");

            if (authlxapp.changeUsername(newName))
            {
                Console.WriteLine($"  ✓ Username changed to '{authlxapp.user_data.username}'");
            }
            else
            {
                Console.WriteLine("  ✗ Username change failed.");
            }
        }

        private static void ExampleForgotPassword(api authlxapp)
        {
            Console.WriteLine("\n── FORGOT PASSWORD (HWID-verified reset) ───────────────");
            Console.WriteLine("  Your current Hardware ID will be used to verify your identity.");
            string user = GetInput("  Username     : ");
            string newPass = GetInput("  New Password : ");

            string hwid = Others.GetHWID(authlxapp.hwid_method);
            string displayHwid = hwid.Length > 20 ? hwid.Substring(0, 20) + "..." : hwid;
            Console.WriteLine($"  Using HWID   : {displayHwid}");

            if (authlxapp.forgot(user, newPass, hwid))
            {
                Console.WriteLine("  ✓ Password reset! You can now log in with your new password.");
            }
            else
            {
                Console.WriteLine("  ✗ Reset failed. Is this HWID bound to the account?");
            }
        }

        private static void ExampleVerifySession(api authlxapp)
        {
            Console.WriteLine("\n── VERIFY SESSION ──────────────────────────────────────");
            if (string.IsNullOrEmpty(authlxapp.session_token))
            {
                Console.WriteLine("  Not logged in.");
                return;
            }
            if (authlxapp.check())
            {
                Console.WriteLine("  ✓ Session is valid.");
            }
            else
            {
                Console.WriteLine("  ✗ Session has expired or been revoked.");
            }
        }

        private static void ExampleVerifyToken(api authlxapp)
        {
            Console.WriteLine("\n── VERIFY STANDALONE TOKEN ─────────────────────────────");
            string token = GetInput("  Token : ");

            if (authlxapp.verifyToken(token))
            {
                Console.WriteLine("  ✓ Token is valid.");
            }
            else
            {
                Console.WriteLine("  ✗ Token is invalid or banned.");
            }
        }

        private static void ExampleLogout(api authlxapp)
        {
            Console.WriteLine("\n── LOGOUT ──────────────────────────────────────────────");
            authlxapp.stop_ban_monitor();
            if (authlxapp.logout())
            {
                Console.WriteLine("  ✓ Logged out successfully.");
            }
            else
            {
                Console.WriteLine("  ✗ Logout failed.");
            }
        }

        private static void ExampleDebugInfo(api authlxapp)
        {
            Console.WriteLine("\n── DEBUG INFO ──────────────────────────────────────────");
            var info = authlxapp.debugInfo();
            foreach (var pair in info)
            {
                string key = pair.Key;
                string val = pair.Value;
                int spaces = 20 - key.Length;
                if (spaces < 1) spaces = 1;
                Console.WriteLine($"  {key}{new string(' ', spaces)} : {val}");
            }
        }

        private static void ExampleHwid(api authlxapp)
        {
            Console.WriteLine("\n── HWID METHODS ────────────────────────────────────────");
            Console.WriteLine($"  windows_user (SID)  : {Others.GetHWID("windows_user")}");
            Console.WriteLine($"  machine (registry)  : {Others.GetHWID("machine")}");
        }

        private static void ExampleAccountDetails(api authlxapp)
        {
            Console.WriteLine("\n── ACCOUNT DETAILS ──────────────────────────────────────");
            if (string.IsNullOrEmpty(authlxapp.user_data.username))
            {
                Console.WriteLine("  Not logged in.");
                return;
            }

            Console.WriteLine($"  Username       : {authlxapp.user_data.username}");
            Console.WriteLine($"  HWID Bound     : {authlxapp.user_data.hwid}");
            Console.WriteLine($"  Subscription   : {(string.IsNullOrEmpty(authlxapp.user_data.subscription) ? "N/A" : authlxapp.user_data.subscription)}");
            Console.WriteLine($"  Expires        : {(string.IsNullOrEmpty(authlxapp.user_data.expires) ? "N/A" : authlxapp.user_data.expires)}");
            Console.WriteLine($"  Last Login     : {(string.IsNullOrEmpty(authlxapp.user_data.lastlogin) ? "N/A" : authlxapp.user_data.lastlogin)}");
            Console.WriteLine($"  Created At     : {(string.IsNullOrEmpty(authlxapp.user_data.createdate) ? "N/A" : authlxapp.user_data.createdate)}");

            if (authlxapp.user_data.subscriptions.Count > 0)
            {
                Console.Write("  All Subs       : [");
                for (int i = 0; i < authlxapp.user_data.subscriptions.Count; ++i)
                {
                    Console.Write($"{{'{authlxapp.user_data.subscriptions[i].subscription}', expiry: '{authlxapp.user_data.subscriptions[i].expiry}'}}");
                    if (i + 1 < authlxapp.user_data.subscriptions.Count)
                    {
                        Console.Write(", ");
                    }
                }
                Console.WriteLine("]");
            }
        }

        static void Main(string[] args)
        {
            // Set console output to support unicode borders and emojis
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("Initialising AuthLX security...");

            // Initialize structured logger
            Logger.Instance.Init("logs/sdk.log", true, LogLevel.DebugLevel);

            api authlxapp = AuthLXApp;

            // Configure allowed hosts locking whitelist
            authlxapp.set_allowed_hosts(new List<string> { "authlx.com" });

            Console.WriteLine($"✓ Initialised in {(string.IsNullOrEmpty(authlxapp.client_secret) ? "OFF" : "SECURE")} mode.");
            Console.WriteLine($"  HWID Method : {authlxapp.hwid_method}");
            Console.WriteLine($"  HWID        : {Others.GetHWID(authlxapp.hwid_method)}");
            string safeHash = authlxapp.hash_to_check.Length > 24 ? authlxapp.hash_to_check.Substring(0, 24) + "..." : authlxapp.hash_to_check;
            Console.WriteLine($"  Hash        : {safeHash}");
            Console.WriteLine();

            GetInput("  Press Enter to continue...");

            bool loggedIn = false;

            while (true)
            {
                ShowBanner(authlxapp);

                if (!loggedIn)
                {
                    string opt = ShowMainMenu();
                    if (opt == "1")
                    {
                        if (ExampleLogin(authlxapp))
                        {
                            loggedIn = true;
                        }
                    }
                    else if (opt == "2")
                    {
                        ExampleRegister(authlxapp);
                    }
                    else if (opt == "3")
                    {
                        if (ExampleWebLogin(authlxapp))
                        {
                            loggedIn = true;
                        }
                    }
                    else if (opt == "4")
                    {
                        ExampleRegisterWeb(authlxapp);
                    }
                    else if (opt == "5")
                    {
                        ExampleForgotPassword(authlxapp);
                    }
                    else if (opt == "6")
                    {
                        ExampleVerifyToken(authlxapp);
                    }
                    else if (opt == "7")
                    {
                        ExampleHwid(authlxapp);
                    }
                    else if (opt == "8")
                    {
                        ExampleDebugInfo(authlxapp);
                    }
                    else if (opt == "0")
                    {
                        break;
                    }
                    else
                    {
                        Console.WriteLine("  Invalid option.");
                    }
                    GetInput("\n  Press Enter to return...");
                }
                else
                {
                    string opt = ShowAccountMenu();
                    if (opt == "1")
                    {
                        ExampleAccountDetails(authlxapp);
                    }
                    else if (opt == "2")
                    {
                        ExampleChangeUsername(authlxapp);
                    }
                    else if (opt == "3")
                    {
                        ExampleUpgrade(authlxapp);
                    }
                    else if (opt == "4")
                    {
                        ExampleVerifySession(authlxapp);
                    }
                    else if (opt == "5")
                    {
                        ExampleLogout(authlxapp);
                        loggedIn = false;
                    }
                    else if (opt == "0")
                    {
                        loggedIn = false;
                    }
                    else
                    {
                        Console.WriteLine("  Invalid option.");
                    }
                    GetInput("\n  Press Enter to return...");
                }
            }

            Console.WriteLine("Exiting...");
        }
    }
}
