using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Web.Administration;

namespace UpdateIISCert
{
	class Program
	{
		static void Main(string[] args)
		{
			// 假设通过命令行参数传入 pfx 路径和密码
			// 例如： Pfx2IIS.exe "D:\certs\mycert.pfx" "pfxpassword" true/false

			if (args.Length < 2)
			{
				Console.WriteLine("用法：Pfx2IIS.exe <pfx路径> <密码> <是否更新主机名为空的站点,true表示更新。>");
				return;
			}
			string pfxPath = args[0];
			string pfxPassword = args[1];
			bool updateEmptyHost = args.Length > 2 && args[2] == "true";    // 是否更新空主机名的站点




			if (!File.Exists(pfxPath))
			{
				Console.WriteLine($"找不到文件：{pfxPath}");
				return;
			}

			try
			{
				// 1. 从 PFX 加载证书
				X509Certificate2 newCert = new X509Certificate2(pfxPath, pfxPassword,
					X509KeyStorageFlags.MachineKeySet |
					X509KeyStorageFlags.PersistKeySet |
					X509KeyStorageFlags.Exportable);

				// 3. 获取证书包含的域名列表（包含 Subject + Subject Alternative Name）
				var allDomains = GetAllDomainsFromCert(newCert);
				Console.WriteLine("证书包含的域名：");
				foreach (var domain in allDomains)
				{
					Console.WriteLine($" - {domain}");
				}


				// 2. 安装证书到本地计算机 Personal (My) 存储区
				//    如果已经存在相同指纹的证书，可以考虑先卸载或覆盖
				InstallCertificateToLocalMachineStore(newCert, allDomains);



				// 4. 遍历本地 IIS 所有站点，更新对应的绑定
				UpdateIISBindings(allDomains, newCert, updateEmptyHost);

				Console.WriteLine("完成：站点绑定已更新为新证书。");
			}
			catch (Exception ex)
			{
				Console.WriteLine("更新证书发生异常： " + ex.Message);
			}
		}

		/// 将证书安装到本地计算机的 My（Personal）存储区，并设置 FriendlyName
		/// </summary>
		/// <param name="cert"></param>
		/// <param name="allDomains">该证书包含的所有域名列表，用于组合 FriendlyName</param>
		private static void InstallCertificateToLocalMachineStore(X509Certificate2 cert, string[] allDomains)
		{
			// 把所有域名用逗号拼起来，或者只取第一个域名
			string domainsSummary = allDomains.Length == 0
				? cert.GetNameInfo(X509NameType.DnsName, false)
				: allDomains.First() + (allDomains.Length > 1 ? $"[*{allDomains.Length}]" : ""); //string.Join(", ", allDomains);

			// 组合一个简洁的 FriendlyName，例如： "*.example.com, example.com (2025-01-01 ~ 2026-01-01)"
			//string friendlyName = $"{domainsSummary} ({cert.NotBefore:yyyy-MM-dd} ~ {cert.NotAfter:yyyy-MM-dd})";
			string friendlyName = $"{domainsSummary} (~{cert.NotAfter:yyyy-MM-dd})";

			// 设置 FriendlyName
			cert.FriendlyName = friendlyName;

			using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
			{
				store.Open(OpenFlags.ReadWrite);

				// 判断是否已存在相同指纹的证书
				var existingCert = store.Certificates
					.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false)
					.OfType<X509Certificate2>()
					.FirstOrDefault();
				if (existingCert == null)
				{
					Console.WriteLine("正在将新证书导入到本地计算机 MY 存储区...");
					store.Add(cert);
				}
				else
				{
					Console.WriteLine("本地计算机 MY 存储区已存在相同指纹的证书，无需再次导入。");
				}
			}
		}


		/// <summary>
		/// 获取证书所有域名（包括 Subject 和 Subject Alternative Name）
		/// 例如，*.getquicker.net, getquicker.net
		/// </summary>
		/// <param name="cert"></param>
		/// <returns></returns>
		private static string[] GetAllDomainsFromCert(X509Certificate2 cert)
		{
			// 1. 证书主题中可能包含 CN=*.getquicker.net
			// 2. 通过解析 Subject Alternative Name (SAN) 获取额外域名信息
			// SAN 通常存储在 X509Extensions 中，OID=2.5.29.17
			var subject = cert.GetNameInfo(X509NameType.DnsName, false);

			// 提取 SAN
			var sanList = cert.Extensions
				.OfType<X509Extension>()
				.Where(e => e.Oid.Value == "2.5.29.17") // Subject Alternative Name OID
				.SelectMany(e => ParseSanExtension(e))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();

			// 把 Subject 也加进去（可能是 *.getquicker.net）
			if (!string.IsNullOrWhiteSpace(subject) && !sanList.Contains(subject, StringComparer.OrdinalIgnoreCase))
			{
				sanList.Add(subject);
			}

			return sanList.ToArray();
		}

		/// <summary>
		/// 解析 SAN Extension，返回所有 DNS 名
		/// </summary>
		/// <param name="extension"></param>
		/// <returns></returns>
		private static string[] ParseSanExtension(X509Extension extension)
		{
			// 如果是 Subject Alternative Name，原始数据一般存储 DNS 名等
			// 可以简单地字符串搜索或使用 BouncyCastle 等库完整解析
			// 这里示例用简单字符串搜索来获取 DNS 名
			var rawData = extension.Format(true);

			// 例如可能包含 "DNS Name=*.getquicker.net"、"DNS Name=getquicker.net"
			var lines = rawData.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

			return lines
				.Where(line => line.Trim().StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
				.Select(line => line.Trim().Substring("DNS Name=".Length))
				.ToArray();
		}

		/// <summary>
		/// 根据证书中的所有域名，遍历 IIS Site Bindings，找到匹配的域名并更新证书
		/// </summary>
		/// <param name="allDomains"></param>
		/// <param name="newCert"></param>
		/// <param name="updateEmptyHost">是否更新空主机名的站点</param>
		private static void UpdateIISBindings(string[] allDomains, X509Certificate2 newCert, bool updateEmptyHost)
		{
			using (ServerManager serverManager = new ServerManager())
			{
				foreach (var site in serverManager.Sites)
				{
					bool siteChanged = false;

					foreach (var binding in site.Bindings)
					{
						// 仅处理 https 协议
						if (!binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase))
							continue;

						// HostName 对应 IIS 里设置的域名
						var bindingDomain = binding.Host?.ToLower() ?? string.Empty;

						// 如果不更新空主机名的站点，跳过
						bool shouldUpdate = (string.IsNullOrEmpty(bindingDomain) && updateEmptyHost)
							|| (!string.IsNullOrEmpty(bindingDomain) && IsDomainMatch(bindingDomain, allDomains));

						
						// 判断是否匹配证书中的域名 (含泛域名逻辑)
						if (shouldUpdate)
						{
							// 更新证书
							binding.CertificateHash = newCert.GetCertHash();
							binding.CertificateStoreName = "My";

							// 若需启用 SNI
							// binding.SetAttributeValue("sslFlags", 1);

							siteChanged = true;
							Console.WriteLine($"已为站点[{site.Name}]绑定域名[{bindingDomain}]更新证书。");
						}
					}

					// 如果站点有变更，保存
					if (siteChanged)
					{
						serverManager.CommitChanges();
					}
				}
			}
		}

		/// <summary>
		/// 判断 bindingDomain 是否匹配证书域名列表
		/// 1. 精确匹配
		/// 2. 对泛域名进行子域名匹配
		/// </summary>
		/// <param name="bindingDomain"></param>
		/// <param name="allDomains"></param>
		/// <returns></returns>
		private static bool IsDomainMatch(string bindingDomain, string[] allDomains)
		{
			// 判断逻辑可按需调整更灵活
			foreach (var certDomain in allDomains)
			{
				// 忽略大小写
				var cd = certDomain.ToLower();

				if (cd.StartsWith("*."))
				{
					// 比如：*.getquicker.net
					var root = cd.Substring(2); // getquicker.net
												// 如果 bindingDomain 是 xxx.getquicker.net，也算匹配
					if (bindingDomain == root || bindingDomain.EndsWith("." + root))
					{
						return true;
					}
				}
				else
				{
					// 直接对比域名
					if (bindingDomain == cd)
					{
						return true;
					}
				}
			}

			return false;
		}
	}
}
