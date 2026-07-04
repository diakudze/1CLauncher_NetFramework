using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CredentialApp
{
    public static class CredentialManager
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredWriteW(ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredReadW(string target, CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CredDeleteW(string target, CRED_TYPE type, int flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr cred);

        private enum CRED_TYPE : uint
        {
            GENERIC = 1
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public long LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        private const string TARGET_NAME = "1CLauncher_UserCredentials";

        public static bool SaveCredentials(string username, string password)
        {
            byte[] passwordBytes = Encoding.Unicode.GetBytes(password);

            CREDENTIAL credential = new CREDENTIAL();
            credential.Type = CRED_TYPE.GENERIC;
            credential.TargetName = TARGET_NAME;
            credential.UserName = username;
            credential.CredentialBlobSize = (uint)passwordBytes.Length;
            credential.CredentialBlob = Marshal.StringToCoTaskMemUni(password);
            credential.Persist = 2;

            return CredWriteW(ref credential, 0);
        }

        public static bool ReadCredentials(out string username, out string password)
        {
            username = null;
            password = null;

            IntPtr credPtr;
            if (!CredReadW(TARGET_NAME, CRED_TYPE.GENERIC, 0, out credPtr))
                return false;

            try
            {
                CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                username = cred.UserName;

                if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
                {
                    password = Marshal.PtrToStringUni(cred.CredentialBlob, (int)cred.CredentialBlobSize / 2);
                }

                return !string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password);
            }
            finally
            {
                CredFree(credPtr);
            }
        }

        public static bool HasCredentials()
        {
            string username;
            string password;
            return ReadCredentials(out username, out password);
        }

        public static bool DeleteCredentials()
        {
            return CredDeleteW(TARGET_NAME, CRED_TYPE.GENERIC, 0);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Система учётных данных ===");
            Console.WriteLine();

            bool resetMode = HasResetKey(args);

            if (resetMode)
            {
                Console.WriteLine("[!] Ключ /changeUser обнаружен - режим перезаписи учётных данных");
                Console.WriteLine();
            }

            string username;
            string password;

            if (resetMode || !CredentialManager.HasCredentials())
            {
                if (!RequestAndSaveCredentials(out username, out password))
                {
                    Console.WriteLine();
                    Console.WriteLine("[X] Ошибка: не удалось сохранить учётные данные");
                    Console.ReadLine();
                    return;
                }

                Console.WriteLine();
                if (resetMode)
                    Console.WriteLine("[OK] Учётные данные перезаписаны в хранилище Windows");
                else
                    Console.WriteLine("[OK] Учётные данные сохранены в хранилище Windows");
            }
            else
            {
                CredentialManager.ReadCredentials(out username, out password);
                Console.WriteLine("[OK] Учётные данные загружены из хранилища Windows");
            }

            Console.WriteLine();
            Console.WriteLine("--- Текущие учётные данные ---");
            Console.WriteLine("Имя пользователя: " + username);
            Console.WriteLine("Пароль:           " + MaskPassword(password));

            Console.WriteLine();
            Console.WriteLine("--- Выполнение команды ---");
            ExecuteCommand(username, password);

            Console.WriteLine();
            Console.ReadLine();
        }

        private static bool HasResetKey(string[] args)
        {
            string[] envArgs = Environment.GetCommandLineArgs();
            for (int i = 1; i < envArgs.Length; i++)
            {
                if (string.Equals(envArgs[i], "/changeUser", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static bool RequestAndSaveCredentials(out string username, out string password)
        {
            Console.WriteLine("=== Ввод учётных данных ===");
            Console.WriteLine();

            Console.Write("Имя пользователя: ");
            username = Console.ReadLine();

            if (string.IsNullOrEmpty(username))
            {
                Console.WriteLine("[!] Имя пользователя не может быть пустым");
                password = null;
                return false;
            }

            Console.Write("Пароль: ");
            string password1 = ReadPasswordSecure();

            if (string.IsNullOrEmpty(password1))
            {
                Console.WriteLine("[!] Пароль не может быть пустым");
                password = null;
                return false;
            }

            Console.Write("Подтвердите пароль: ");
            string password2 = ReadPasswordSecure();

            if (password1 != password2)
            {
                Console.WriteLine("[!] Пароли не совпадают!");
                password = null;
                return false;
            }

            password = password1;

            return CredentialManager.SaveCredentials(username, password);
        }

        private static void ExecuteCommand(string username, string password)
        {
            Console.WriteLine("[ТЕСТ] Команда выполнена успешно!");
            Console.WriteLine("[ТЕСТ] Использованы учётные данные:");
            Console.WriteLine("       - Пользователь: " + username);
            Console.WriteLine("       - Пароль: " + MaskPassword(password));
        }

        private static string ReadPasswordSecure()
        {
            StringBuilder password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo keyInfo = Console.ReadKey(true);

                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                else if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    password.Append(keyInfo.KeyChar);
                    Console.Write("*");
                }
            }
            return password.ToString();
        }

        private static string MaskPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return "(пусто)";

            if (password.Length <= 2)
            {
                return new string('*', password.Length);
            }

            return password.Substring(0, 2) + new string('*', password.Length - 2);
        }
    }
}