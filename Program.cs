using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

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
            string tmpUser;
            string tmpPass;
            return ReadCredentials(out tmpUser, out tmpPass);
        }

        public static bool DeleteCredentials()
        {
            return CredDeleteW(TARGET_NAME, CRED_TYPE.GENERIC, 0);
        }
    }

    /// <summary>
    /// Читает настройки из файла Settings.txt.
    /// Поддерживает JSON и INI-стиль.
    /// </summary>
    public static class SettingsReader
    {
        private const string SETTINGS_FILE_NAME = "Settings.txt";

        public static string GetSettingsFilePath()
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            return Path.Combine(appDir, SETTINGS_FILE_NAME);
        }

        public static Dictionary<string, string> ReadAllSettings()
        {
            string path = GetSettingsFilePath();

            if (!File.Exists(path))
                throw new FileNotFoundException("Файл настроек не найден: " + path);

            string content = File.ReadAllText(path, Encoding.UTF8).Trim();

            if (content.StartsWith("{"))
                return ParseJson(content);
            else
                return ParseIni(content);
        }

        public static string GetValue(string key)
        {
            return GetValue(key, null);
        }

        public static string GetValue(string key, string defaultValue)
        {
            try
            {
                Dictionary<string, string> settings = ReadAllSettings();
                string value;
                if (settings.TryGetValue(key, out value))
                    return value;
            }
            catch
            {
                // игнор
            }
            return defaultValue;
        }

        /// <summary>
        /// Минимальный JSON-парсер без внешних зависимостей.
        /// Поддерживает плоский объект { "key": "value", ... }.
        /// </summary>
        private static Dictionary<string, string> ParseJson(string json)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Обычная строка с escape-символами (совместимо с C# 3.0)
            string pattern = "\"(?<key>[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"\\s*:\\s*\"(?<value>[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"";
            Regex regex = new Regex(pattern, RegexOptions.Compiled);

            foreach (Match m in regex.Matches(json))
            {
                string key = UnescapeJson(m.Groups["key"].Value);
                string value = UnescapeJson(m.Groups["value"].Value);
                result[key] = value;
            }

            return result;
        }

        private static string UnescapeJson(string s)
        {
            return s.Replace("\\\\", "\u0001")
                    .Replace("\\\"", "\"")
                    .Replace("\\n", "\n")
                    .Replace("\\r", "\r")
                    .Replace("\\t", "\t")
                    .Replace("\u0001", "\\");
        }

        private static Dictionary<string, string> ParseIni(string content)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] lines = content.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();

                if (string.IsNullOrEmpty(line) || line.StartsWith("#") || line.StartsWith("//"))
                    continue;

                int eqIndex = line.IndexOf('=');
                if (eqIndex < 0) continue;

                string key = line.Substring(0, eqIndex).Trim();
                string value = line.Substring(eqIndex + 1).Trim();

                if (value.Length >= 2 && value.StartsWith("\"") && value.EndsWith("\""))
                    value = value.Substring(1, value.Length - 2);

                result[key] = value;
            }

            return result;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== 1C Launcher ===");
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

            Console.WriteLine();
            Console.WriteLine("--- Чтение настроек и запуск приложения ---");
            ExecuteCommandWithSettings(username, password);

            // Приложение закрывается автоматически после успешного запуска
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

        private static void ExecuteCommandWithSettings(string username, string password)
        {
            // 1. Читаем настройки
            Dictionary<string, string> settings;
            try
            {
                settings = SettingsReader.ReadAllSettings();
                Console.WriteLine("[OK] Файл настроек прочитан: " + SettingsReader.GetSettingsFilePath());
                Console.WriteLine("[OK] Загружено параметров: " + settings.Count);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Ошибка чтения настроек: " + ex.Message);
                Console.WriteLine("[X] Запуск приложения отменён.");
                Console.WriteLine();
                Console.WriteLine("Нажмите любую клавишу для выхода...");
                Console.ReadKey();
                return;
            }

            // 2. Получаем путь к 1С
            string pathToApp;
            if (!settings.TryGetValue("PATH_TO_APP", out pathToApp))
            {
                Console.WriteLine("[X] Параметр PATH_TO_APP не найден в файле настроек!");
                Console.WriteLine("[X] Запуск приложения отменён.");
                Console.WriteLine();
                Console.WriteLine("Нажмите любую клавишу для выхода...");
                Console.ReadKey();
                return;
            }

            if (!File.Exists(pathToApp))
            {
                Console.WriteLine("[X] Файл не найден: " + pathToApp);
                Console.WriteLine("[X] Проверьте параметр PATH_TO_APP в Settings.txt");
                Console.WriteLine();
                Console.WriteLine("Нажмите любую клавишу для выхода...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("[OK] Приложение найдено: " + pathToApp);

            // 3. Получаем режим запуска (MODE)
            string mode;
            if (!settings.TryGetValue("MODE", out mode) || string.IsNullOrEmpty(mode))
            {
                mode = "ENTERPRISE";
                Console.WriteLine("[!] Параметр MODE не указан, используется значение по умолчанию: ENTERPRISE");
            }
            else
            {
                Console.WriteLine("[OK] Режим запуска: " + mode);
            }

            // 4. Собираем аргументы командной строки для 1С
            StringBuilder argsBuilder = new StringBuilder();

            string baseConnection;
            if (settings.TryGetValue("BASE_CONNECTION", out baseConnection)
                && !string.IsNullOrEmpty(baseConnection))
            {
                argsBuilder.Append(mode).Append(" ").Append(baseConnection);
            }
            else
            {
                argsBuilder.Append(mode);
            }

            // Добавляем логин и пароль
            argsBuilder.Append(" /N\"").Append(username).Append("\"");
            argsBuilder.Append(" /P\"").Append(password).Append("\"");

            // Дополнительные аргументы
            string additionalArgs;
            if (settings.TryGetValue("ADDITIONAL_ARGS", out additionalArgs)
                && !string.IsNullOrEmpty(additionalArgs))
            {
                argsBuilder.Append(" ").Append(additionalArgs);
            }

            string arguments = argsBuilder.ToString().Trim();

            // 5. Логируем (пароль маскируем!)
            string safeArgs = arguments.Replace(password, new string('*', Math.Max(password.Length, 3)));
            Console.WriteLine("[>] Запуск: \"" + pathToApp + "\"");
            Console.WriteLine("[>] Аргументы: " + safeArgs);

            // 6. Запускаем процесс
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = pathToApp;
                psi.Arguments = arguments;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = false;

                Process process = Process.Start(psi);
                Console.WriteLine("[OK] Процесс запущен (PID: " + process.Id + ")");
                // Успешный запуск - приложение закроется автоматически
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Ошибка запуска: " + ex.Message);
                Console.WriteLine();
                Console.WriteLine("Нажмите любую клавишу для выхода...");
                Console.ReadKey();
            }
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
                return new string('*', password.Length);

            return password.Substring(0, 2) + new string('*', password.Length - 2);
        }
    }
}