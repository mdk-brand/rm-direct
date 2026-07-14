using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Threading;
using System.Windows.Forms;

namespace RmDirect
{
    internal static class Program
    {
        private const string SingleInstanceMutexName = @"Local\RmDirectSingleInstance";

        [STAThread]
        private static void Main()
        {
            bool isFirstInstance;

            using (var singleInstanceMutex = new Mutex(true, SingleInstanceMutexName, out isFirstInstance))
            {
                if (!isFirstInstance)
                {
                    TrayAppContext.OpenService();
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new TrayAppContext());
                GC.KeepAlive(singleInstanceMutex);
            }
        }
    }

    internal sealed class TrayAppContext : ApplicationContext
    {
        private const string Url = "http://127.0.0.1:8123/index.html";
        private readonly NotifyIcon trayIcon;
        private Process serverProcess;

        public TrayAppContext()
        {
            trayIcon = new NotifyIcon
            {
                Icon = SystemIcons.Application,
                Text = "rm-direct",
                Visible = true,
                ContextMenuStrip = BuildMenu()
            };
            trayIcon.DoubleClick += (sender, args) => OpenService();

            StartServer();
            OpenService();
        }

        private ContextMenuStrip BuildMenu()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Открыть", null, (sender, args) => OpenService());
            menu.Items.Add("Перезапустить сервер", null, (sender, args) => RestartServer());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Выход", null, (sender, args) => Exit());
            return menu;
        }

        private void StartServer()
        {
            var appDirectory = AppDomain.CurrentDomain.BaseDirectory;
            var nodePath = Path.Combine(appDirectory, "runtime", "node.exe");
            var serverPath = Path.Combine(appDirectory, "server.js");

            if (!File.Exists(nodePath) || !File.Exists(serverPath))
            {
                MessageBox.Show(
                    "Не найден runtime\\node.exe или server.js рядом с приложением.",
                    "rm-direct",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            try
            {
                serverProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = nodePath,
                        Arguments = "\"" + serverPath + "\"",
                        WorkingDirectory = appDirectory,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    },
                    EnableRaisingEvents = true
                };

                serverProcess.Start();
                WaitForServer();
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось запустить сервер: " + error.Message,
                    "rm-direct",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void RestartServer()
        {
            StopServer();
            StartServer();
        }

        private void StopServer()
        {
            try
            {
                if (serverProcess != null && !serverProcess.HasExited)
                {
                    serverProcess.Kill();
                    serverProcess.WaitForExit(3000);
                }
            }
            catch
            {
            }
            finally
            {
                if (serverProcess != null)
                {
                    serverProcess.Dispose();
                    serverProcess = null;
                }
            }
        }

        private static void WaitForServer()
        {
            for (var attempt = 0; attempt < 30; attempt++)
            {
                try
                {
                    var request = (HttpWebRequest)WebRequest.Create(Url);
                    request.Timeout = 500;
                    request.Method = "GET";

                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        if ((int)response.StatusCode >= 200 && (int)response.StatusCode < 500)
                        {
                            return;
                        }
                    }
                }
                catch
                {
                    Thread.Sleep(200);
                }
            }
        }

        internal static void OpenService()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Url,
                    UseShellExecute = true
                });
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "Не удалось открыть страницу: " + error.Message,
                    "rm-direct",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void ShowBalloon(string title, string text)
        {
            trayIcon.BalloonTipTitle = title;
            trayIcon.BalloonTipText = text;
            trayIcon.ShowBalloonTip(3000);
        }

        private void Exit()
        {
            trayIcon.Visible = false;
            StopServer();
            Application.Exit();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                trayIcon.Dispose();
                StopServer();
            }

            base.Dispose(disposing);
        }
    }
}
