using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using Microsoft.Win32;

namespace OTBaselineCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            List<CheckItem> report = new List<CheckItem>();
            int totalScore = 0;
            int maxScore = 4;
            string checkTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string computerName = Environment.MachineName;

            Console.WriteLine("========================================");
            Console.WriteLine("      制造业OT基线检查（Agent端）");
            Console.WriteLine("========================================");
            Console.WriteLine("检查时间: " + checkTime);
            Console.WriteLine("主机名称: " + computerName);
            Console.WriteLine("");

            // 1. 172.20网卡信息
            Console.WriteLine("[1/5] 采集172.20网段网络信息...");
            NetInfo netInfo = Get172NetworkInfo();
            report.Add(new CheckItem("IP与MAC地址(172.20)", "信息", netInfo.Detail, 0));

            // 2. 火绒病毒码
            Console.WriteLine("[2/5] 检查火绒安全软件病毒码...");
            CheckItem huorong = CheckHuorong();
            report.Add(huorong);
            totalScore += huorong.Score;

            // 3. Admin账户
            Console.WriteLine("[3/5] 检查默认管理员账户...");
            CheckItem admin = CheckAdmin();
            report.Add(admin);
            totalScore += admin.Score;

            // 4. 445/139配置（以网卡属性为准）
            Console.WriteLine("[4/5] 检查172.20网段445/139配置...");
            CheckItem ports = CheckPortConfig172(netInfo);
            report.Add(ports);
            totalScore += ports.Score;

            // 5. LanmanServer
            Console.WriteLine("[5/5] 检查LanmanServer服务...");
            CheckItem server = CheckLanmanServer();
            report.Add(server);
            totalScore += server.Score;

            // 汇总
            Console.WriteLine("");
            Console.WriteLine("========================================");
            Console.WriteLine("           检查结果汇总");
            Console.WriteLine("========================================");
            Console.WriteLine("{0,-22} {1,-8} {2,-6} {3}", "检查项", "状态", "得分", "详情");
            Console.WriteLine(new string('-', 90));
            foreach (CheckItem item in report)
            {
                string name = item.Name;
                if (name.Length > 22) name = name.Substring(0, 22);
                Console.WriteLine("{0,-22} {1,-8} {2,-6} {3}", name, item.Status, item.Score, item.Detail);
            }

            double rate = Math.Round((double)totalScore / maxScore * 100, 1);
            string passStatus = totalScore == maxScore ? "通过" : "不通过";
            Console.WriteLine("");
            Console.WriteLine("综合得分: {0}/{1} ({2}%) - {3}", totalScore, maxScore, rate, passStatus);

            // 生成报告
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string htmlPath = Path.Combine(Path.GetTempPath(), "OT_Baseline_Report_" + timestamp + ".html");
            string csvPath = Path.Combine(Path.GetTempPath(), "OT_Baseline_" + computerName + "_" + timestamp + ".csv");

            GenerateHtml(htmlPath, report, totalScore, maxScore, rate, passStatus, checkTime, computerName, netInfo);
            GenerateCsv(csvPath, report, totalScore, maxScore, rate, passStatus, checkTime, computerName, netInfo);

            Console.WriteLine("");
            Console.WriteLine("HTML报告: " + htmlPath);
            Console.WriteLine("CSV记录:  " + csvPath);

            try
            {
                System.Diagnostics.Process.Start("explorer.exe", htmlPath);
                Console.WriteLine("报告已在浏览器中打开");
            }
            catch
            {
                Console.WriteLine("请手动复制HTML路径到浏览器打开");
            }

            Console.WriteLine("");
            Console.WriteLine("========================================");
            Console.Write("按回车键退出...");
            Console.ReadLine();
        }

        static NetInfo Get172NetworkInfo()
        {
            StringBuilder sb = new StringBuilder();
            List<IPAddress> ips = new List<IPAddress>();
            string guid = "";

            try
            {
                NetworkInterface[] allNics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface nic in allNics)
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;

                    IPInterfaceProperties props = nic.GetIPProperties();
                    foreach (UnicastIPAddressInformation addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                        string ipStr = addr.Address.ToString();
                        if (ipStr.StartsWith("172.20."))
                        {
                            ips.Add(addr.Address);
                            guid = nic.Id;
                            sb.AppendFormat("{0}: IP={1}, MAC={2}\n", nic.Name, ipStr, nic.GetPhysicalAddress());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("读取网络信息失败: " + ex.Message);
            }

            if (ips.Count == 0)
            {
                sb.AppendLine("未找到172.20网段的网卡");
            }

            return new NetInfo(sb.ToString().Trim(), ips, guid);
        }

        static CheckItem CheckHuorong()
        {
            string[] possiblePaths = new string[] {
                @"C:\Program Files (x86)\Huorong",
                @"C:\Program Files\Huorong",
                @"C:\ProgramData\Huorong",
                @"D:\Huorong",
                @"D:\Program Files (x86)\Huorong",
                @"D:\Program Files\Huorong",
                @"E:\Huorong"
            };

            string installPath = null;
            foreach (string path in possiblePaths)
            {
                if (Directory.Exists(path))
                {
                    installPath = path;
                    break;
                }
            }

            bool isRunning = false;
            string foundProcess = "";
            try
            {
                System.Diagnostics.Process[] allProcs = System.Diagnostics.Process.GetProcesses();
                foreach (System.Diagnostics.Process proc in allProcs)
                {
                    try
                    {
                        string pname = proc.ProcessName.ToLower();
                        string ppath = "";
                        try { ppath = proc.MainModule.FileName.ToLower(); } catch { }

                        if (pname == "hipstray" || pname == "hipsmain" ||
                            pname == "hipsdaemon" || pname == "sysdiag" ||
                            pname == "hrtray" ||
                            ppath.Contains(@"\huorong\") || ppath.Contains(@"\huorong"))
                        {
                            isRunning = true;
                            foundProcess = proc.ProcessName;
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }

            if (!isRunning)
            {
                try
                {
                    ManagementObjectSearcher svcSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='HipsDaemon' OR DisplayName LIKE '%Huorong%'");
                    ManagementObjectCollection svcResults = svcSearcher.Get();
                    if (svcResults.Count > 0)
                    {
                        isRunning = true;
                        foundProcess = "HipsDaemon(服务)";
                    }
                }
                catch { }
            }

            if (installPath == null && !isRunning)
            {
                return new CheckItem("火绒病毒码", "需确认", "未检测到火绒安全软件", 0);
            }

            DateTime? virusDbDate = null;
            string dbSource = "";

            string[] virdbPaths = new string[] {
                Path.Combine(@"C:\ProgramData\Huorong", "Sysdiag", "virdb"),
                Path.Combine(@"C:\ProgramData\Huorong", "Sysdiag", "virlib"),
                Path.Combine(installPath != null ? installPath : "", "Sysdiag", "virdb"),
                Path.Combine(installPath != null ? installPath : "", "Sysdiag", "virlib")
            };

            DateTime latestVirdb = DateTime.MinValue;
            foreach (string vpath in virdbPaths)
            {
                if (!Directory.Exists(vpath)) continue;
                try
                {
                    string[] files = Directory.GetFiles(vpath, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (string file in files)
                    {
                        string ext = Path.GetExtension(file).ToLower();
                        if (ext != ".db" && ext != ".dat" && ext != ".vir" && ext != ".vdb" && ext != ".sig") continue;

                        DateTime dt = File.GetLastWriteTime(file);
                        if (dt > latestVirdb) latestVirdb = dt;
                    }
                }
                catch { }
            }

            if (latestVirdb != DateTime.MinValue)
            {
                virusDbDate = latestVirdb;
                dbSource = "virdb目录";
            }

            if (!virusDbDate.HasValue)
            {
                try
                {
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Huorong\Sysdiag\AppInfo");
                    if (key != null)
                    {
                        object val = key.GetValue("VirusLibVer");
                        if (val != null)
                        {
                            string verStr = val.ToString();
                            DateTime dt;
                            if (DateTime.TryParse(verStr, out dt))
                            {
                                virusDbDate = dt;
                                dbSource = "注册表";
                            }
                        }
                        key.Close();
                    }
                }
                catch { }
            }

            if (!virusDbDate.HasValue)
            {
                try
                {
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Huorong\Sysdiag\AppInfo");
                    if (key != null)
                    {
                        object val = key.GetValue("VirusLibVer");
                        if (val != null)
                        {
                            string verStr = val.ToString();
                            DateTime dt;
                            if (DateTime.TryParse(verStr, out dt))
                            {
                                virusDbDate = dt;
                                dbSource = "注册表(WOW64)";
                            }
                        }
                        key.Close();
                    }
                }
                catch { }
            }

            if (!virusDbDate.HasValue && installPath != null)
            {
                try
                {
                    string[] allFiles = Directory.GetFiles(installPath, "*.*", SearchOption.AllDirectories);
                    DateTime latest = DateTime.MinValue;
                    foreach (string file in allFiles)
                    {
                        string ext = Path.GetExtension(file).ToLower();
                        string dir = Path.GetDirectoryName(file).ToLower();
                        if ((ext == ".db" || ext == ".dat" || ext == ".vir") 
                            && !dir.Contains("log") && !dir.Contains("temp") && !dir.Contains("cache"))
                        {
                            DateTime dt = File.GetLastWriteTime(file);
                            if (dt > latest) latest = dt;
                        }
                    }
                    if (latest != DateTime.MinValue)
                    {
                        virusDbDate = latest;
                        dbSource = "安装目录";
                    }
                }
                catch { }
            }

            string runStatus = isRunning ? "运行中(" + foundProcess + ")" : "未运行";

            if (virusDbDate.HasValue)
            {
                int daysDiff = (DateTime.Now - virusDbDate.Value).Days;
                string dateStr = virusDbDate.Value.ToString("yyyy-MM-dd");

                if (daysDiff <= 3)
                {
                    return new CheckItem("火绒病毒码", "通过", 
                        string.Format("火绒{0}，病毒库({1}): {2}，距今{3}天", runStatus, dbSource, dateStr, daysDiff), 1);
                }
                else
                {
                    return new CheckItem("火绒病毒码", "不通过", 
                        string.Format("火绒{0}，病毒库({1})最后更新: {2}，距今{3}天", runStatus, dbSource, dateStr, daysDiff), 0);
                }
            }
            else
            {
                return new CheckItem("火绒病毒码", "需确认", 
                    string.Format("火绒{0}，无法自动读取病毒库日期，请人工确认火绒主界面显示的病毒库版本", runStatus), 0);
            }
        }

        static CheckItem CheckAdmin()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True AND Name='Administrator'");
                ManagementObjectCollection results = searcher.Get();
                if (results.Count == 0)
                {
                    return new CheckItem("默认Admin账户", "通过", "未找到Administrator账户（已重命名或删除）", 1);
                }
                foreach (ManagementObject user in results)
                {
                    bool disabled = (bool)user["Disabled"];
                    if (disabled)
                    {
                        return new CheckItem("默认Admin账户", "通过", "Administrator账户已禁用", 1);
                    }
                    else
                    {
                        return new CheckItem("默认Admin账户", "不通过", "Administrator账户仍为启用状态", 0);
                    }
                }
            }
            catch (Exception ex)
            {
                return new CheckItem("默认Admin账户", "异常", "检查失败: " + ex.Message, 0);
            }
            return new CheckItem("默认Admin账户", "异常", "未知错误", 0);
        }

        static CheckItem CheckPortConfig172(NetInfo netInfo)
        {
            if (netInfo.IPs == null || netInfo.IPs.Count == 0)
            {
                return new CheckItem("端口445/139配置", "信息", "未找到172.20网段网卡，跳过检查", 0);
            }

            string targetGuid = netInfo.Guid;
            if (string.IsNullOrEmpty(targetGuid))
            {
                return new CheckItem("端口445/139配置", "异常", "无法获取172.20网卡GUID", 0);
            }

            // ====== 检查139: NetBIOS配置 ======
            bool netbiosDisabled = false;
            string netbiosDetail = "";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True");
                ManagementObjectCollection results = searcher.Get();
                foreach (ManagementObject mo in results)
                {
                    string[] ips = mo["IPAddress"] as string[];
                    if (ips == null) continue;
                    bool isTarget = false;
                    foreach (string ip in ips)
                    {
                        if (ip != null && ip.StartsWith("172.20.")) { isTarget = true; break; }
                    }
                    if (!isTarget) continue;

                    object val = mo["TcpipNetbiosOptions"];
                    if (val != null)
                    {
                        int option = Convert.ToInt32(val);
                        if (option == 2)
                        {
                            netbiosDisabled = true;
                            netbiosDetail = "NetBIOS已禁用";
                        }
                        else if (option == 1)
                        {
                            netbiosDetail = "NetBIOS已启用";
                        }
                        else
                        {
                            netbiosDetail = "NetBIOS为默认设置(可能启用)";
                        }
                    }
                    else
                    {
                        netbiosDetail = "无法读取NetBIOS设置";
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                netbiosDetail = "检查NetBIOS失败: " + ex.Message;
            }

            // ====== 检查445: 文件和打印机共享绑定 ======
            bool fileSharingUnbound = false;
            string sharingDetail = "";
            try
            {
                string guidClean = targetGuid.Trim('{', '}').ToLower();

                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Linkage");
                if (key != null)
                {
                    string[] bindList = key.GetValue("Bind") as string[];
                    if (bindList != null && bindList.Length > 0)
                    {
                        bool found = false;
                        foreach (string bind in bindList)
                        {
                            if (bind != null && bind.ToLower().Contains(guidClean))
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            fileSharingUnbound = true;
                            sharingDetail = "文件和打印机共享未绑定到172.20网卡";
                        }
                        else
                        {
                            sharingDetail = "文件和打印机共享已绑定到172.20网卡";
                        }
                    }
                    else
                    {
                        fileSharingUnbound = true;
                        sharingDetail = "文件和打印机共享未绑定任何网卡";
                    }
                    key.Close();
                }
                else
                {
                    fileSharingUnbound = true;
                    sharingDetail = "LanmanServer未配置网卡绑定";
                }
            }
            catch (Exception ex)
            {
                sharingDetail = "检查文件共享绑定失败: " + ex.Message;
            }

            // ====== 合并结果 ======
            if (netbiosDisabled && fileSharingUnbound)
            {
                return new CheckItem("端口445/139配置", "通过", 
                    "139: " + netbiosDetail + "; 445: " + sharingDetail, 1);
            }
            else
            {
                string detail = "";
                if (!netbiosDisabled) detail += "139: " + netbiosDetail;
                if (!fileSharingUnbound) 
                {
                    if (detail.Length > 0) detail += "; ";
                    detail += "445: " + sharingDetail;
                }
                return new CheckItem("端口445/139配置", "不通过", detail, 0);
            }
        }

        static CheckItem CheckLanmanServer()
        {
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='LanmanServer'");
                ManagementObjectCollection results = searcher.Get();
                if (results.Count == 0)
                {
                    return new CheckItem("LanmanServer服务", "通过", "未找到LanmanServer服务", 1);
                }
                foreach (ManagementObject svc in results)
                {
                    string state = svc["State"] != null ? svc["State"].ToString() : "未知";
                    string startMode = svc["StartMode"] != null ? svc["StartMode"].ToString() : "未知";

                    if (state == "Stopped" && startMode == "Disabled")
                    {
                        return new CheckItem("LanmanServer服务", "通过", "已停止且禁用（启动类型: " + startMode + "）", 1);
                    }
                    else if (state == "Stopped")
                    {
                        return new CheckItem("LanmanServer服务", "不通过", "已停止但启动类型为: " + startMode + "（建议禁用）", 0);
                    }
                    else
                    {
                        return new CheckItem("LanmanServer服务", "不通过", "正在运行（状态: " + state + "，启动类型: " + startMode + "）", 0);
                    }
                }
            }
            catch (Exception ex)
            {
                return new CheckItem("LanmanServer服务", "异常", "检查失败: " + ex.Message, 0);
            }
            return new CheckItem("LanmanServer服务", "异常", "未知错误", 0);
        }

        static void GenerateHtml(string path, List<CheckItem> report, int totalScore, int maxScore, double rate, string passStatus, string checkTime, string computerName, NetInfo netInfo)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>OT基线检查报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body{font-family:'Microsoft YaHei',sans-serif;max-width:900px;margin:30px auto;padding:20px;background:#f0f2f5}");
            sb.AppendLine("h1{color:#1a237e;border-bottom:3px solid #3949ab;padding-bottom:12px}");
            sb.AppendLine(".info-box{background:#fff;padding:15px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08);margin-bottom:20px}");
            sb.AppendLine(".info-box p{margin:6px 0;color:#555}");
            sb.AppendLine("table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-radius:8px;overflow:hidden}");
            sb.AppendLine("th{background:#3949ab;color:#fff;padding:14px;text-align:left;font-weight:500}");
            sb.AppendLine("td{padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top}");
            sb.AppendLine("tr:hover{background:#f8f9fa}");
            sb.AppendLine(".pass{color:#2e7d32;font-weight:bold}");
            sb.AppendLine(".fail{color:#c62828;font-weight:bold}");
            sb.AppendLine(".warn{color:#ef6c00;font-weight:bold}");
            sb.AppendLine(".info{color:#1565c0;font-weight:bold}");
            sb.AppendLine(".score-box{text-align:center;padding:20px;background:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08);margin:20px 0}");
            sb.AppendLine(".score{font-size:32px;font-weight:bold}");
            sb.AppendLine(".score-pass{color:#2e7d32}");
            sb.AppendLine(".score-fail{color:#c62828}");
            sb.AppendLine(".footer{color:#888;font-size:12px;margin-top:30px;text-align:center}");
            sb.AppendLine("</style></head><body>");
            sb.AppendLine("<h1>制造业OT基线检查报告</h1>");
            sb.AppendLine("<div class=\"info-box\">");
            sb.AppendLine("<p><b>检查时间:</b> " + checkTime + "</p>");
            sb.AppendLine("<p><b>主机名称:</b> " + computerName + "</p>");
            sb.AppendLine("<p><b>网络信息(172.20网段):</b><br>" + netInfo.Detail.Replace("\n", "<br>") + "</p>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"score-box\">");
            string scoreClass = totalScore == maxScore ? "score-pass" : "score-fail";
            sb.AppendLine("<div class=\"score " + scoreClass + "\">" + totalScore + "/" + maxScore + " (" + rate + "%) — " + passStatus + "</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th style=\"width:20%\">检查项</th><th style=\"width:10%\">状态</th><th>详情</th><th style=\"width:8%\">得分</th></tr>");

            foreach (CheckItem item in report)
            {
                string cls = "warn";
                if (item.Status == "通过") cls = "pass";
                else if (item.Status == "不通过") cls = "fail";
                else if (item.Status == "信息") cls = "info";

                sb.AppendLine("<tr><td>" + item.Name + "</td><td class=\"" + cls + "\">" + item.Status + "</td><td>" + item.Detail + "</td><td>" + item.Score + "</td></tr>");
            }

            sb.AppendLine("</table>");
            sb.AppendLine("<div class=\"footer\">OT Security Baseline Check | Agent端 | 只读检查 | 自动生成</div>");
            sb.AppendLine("</body></html>");

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        static void GenerateCsv(string path, List<CheckItem> report, int totalScore, int maxScore, double rate, string passStatus, string checkTime, string computerName, NetInfo netInfo)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("主机名,IP地址,MAC地址,检查时间,火绒状态,病毒码详情,Admin账户,端口配置,Server服务,综合得分,总评");

            string ip = "N/A";
            string mac = "N/A";
            if (netInfo.IPs.Count > 0)
            {
                ip = netInfo.IPs[0].ToString();
                string[] lines = netInfo.Detail.Split('\n');
                if (lines.Length > 0)
                {
                    string[] parts = lines[0].Split(new string[] { "MAC=" }, StringSplitOptions.None);
                    if (parts.Length > 1) 
                    {
                        string[] macParts = parts[1].Split(',');
                        if (macParts.Length > 0) mac = macParts[0].Trim();
                    }
                }
            }

            string huorongStatus = GetStatusByName(report, "火绒病毒码");
            string huorongDetail = GetDetailByName(report, "火绒病毒码");
            string adminStatus = GetStatusByName(report, "默认Admin账户");
            string portsStatus = GetStatusByName(report, "端口445/139配置");
            string serverStatus = GetStatusByName(report, "LanmanServer服务");

            sb.AppendFormat("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",\"{6}\",\"{7}\",\"{8}\",\"{9}/{10}\",\"{11}\"",
                computerName, ip, mac, checkTime, huorongStatus, huorongDetail, adminStatus, portsStatus, serverStatus, totalScore, maxScore, passStatus);
            sb.AppendLine();

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        static string GetStatusByName(List<CheckItem> report, string name)
        {
            foreach (CheckItem item in report)
            {
                if (item.Name.Contains(name)) return item.Status;
            }
            return "N/A";
        }

        static string GetDetailByName(List<CheckItem> report, string name)
        {
            foreach (CheckItem item in report)
            {
                if (item.Name.Contains(name)) return item.Detail;
            }
            return "N/A";
        }
    }

    class CheckItem
    {
        public string Name { get; set; }
        public string Status { get; set; }
        public string Detail { get; set; }
        public int Score { get; set; }

        public CheckItem(string name, string status, string detail, int score)
        {
            Name = name;
            Status = status;
            Detail = detail;
            Score = score;
        }
    }

    class NetInfo
    {
        public string Detail { get; set; }
        public List<IPAddress> IPs { get; set; }
        public string Guid { get; set; }

        public NetInfo(string detail, List<IPAddress> ips)
        {
            Detail = detail;
            IPs = ips != null ? ips : new List<IPAddress>();
            Guid = "";
        }

        public NetInfo(string detail, List<IPAddress> ips, string guid)
        {
            Detail = detail;
            IPs = ips != null ? ips : new List<IPAddress>();
            Guid = guid != null ? guid : "";
        }
    }
}
