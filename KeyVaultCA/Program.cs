using KeyVaultCa.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;

namespace KeyVaultCA
{
    class Program
    {
        //public class Options
        //{
        //    // General options for the KeyVault access

        //    [Option("appId", Required = true, HelpText = "AppId of the AAD service principal that can access KeyVault.")]
        //    public string AppId { get; set; }

        //    [Option("secret", Required = true, HelpText = "Password of the AAD service principal that can access KeyVault.")]
        //    public string Secret { get; set; }

        //    [Option("kvUrl", Required = true, HelpText = "Key Vault URL")]
        //    public string KeyVaultUrl { get; set; }

        //    // Certificates

        //    [Option("issuercert", Required = true, HelpText = "Name of the issuing certificate in KeyVault.")]
        //    public string IssuerCertName { get; set; }

        //    // Options for the end entity certificate

        //    [Option("csrPath", Required = false, HelpText = "Path to the CSR file in .der format")]
        //    public string PathToCsr { get; set; }

        //    [Option("output", Required = false, HelpText = "Output file name for the certificate")]
        //    public string OutputFileName { get; set; }

        //    // Options for Root CA creation

        //    [Option("ca", Required = false, HelpText = "Should register Root CA")]
        //    public bool IsRootCA { get; set; }

        //    [Option("subject", Required = false, HelpText = "Subject in the format 'C=US, ST=WA, L=Redmond, O=Contoso, OU=Contoso HR, CN=Contoso Inc'")]
        //    public string Subject { get; set; }
        //}

        static async Task Main(string[] args)
        {
            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .AddCommandLine(args)
                .AddEnvironmentVariables()
                .Build();

            await CreateCertificate(config);
        }

        private static async Task CreateCertificate(IConfiguration config)
        {
            var estConfig = new EstConfiguration();
            config.Bind("KeyVault", estConfig);

            var csrConfig = new CsrConfiguration();
            config.Bind("Csr", csrConfig);

            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("KeyVaultCa.Program", LogLevel.Information)
                    .AddFilter("KeyVaultCa.Core", LogLevel.Information)
                    .AddConsole();
            });

            ILogger logger = loggerFactory.CreateLogger<Program>();
            logger.LogInformation("KeyVaultCA app started.");

            var keyVaultServiceClient = new KeyVaultServiceClient(estConfig, loggerFactory.CreateLogger<KeyVaultServiceClient>());
            var kvCertProvider = new KeyVaultCertificateProvider(keyVaultServiceClient, loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

            if (csrConfig.IsRootCA)
            {
                if (string.IsNullOrEmpty(estConfig.Subject))
                {
                    logger.LogError("Certificate subject is not provided.");
                    Environment.Exit(0);
                }

                // Generate issuing certificate in KeyVault
                await kvCertProvider.CreateCACertificateAsync(estConfig.IssuingCA, estConfig.Subject);
                logger.LogInformation("CA certificate was created successfully and can be found in the Key Vault {kvUrl}.", estConfig.KeyVaultUrl);
            }
            else
            {
                if (string.IsNullOrEmpty(csrConfig.PathToCsr) || string.IsNullOrEmpty(csrConfig.OutputFileName))
                {
                    logger.LogError("Path to CSR or the Output Filename is not provided.");
                    Environment.Exit(0);
                }

                // Issue device certificate
                var csr = File.ReadAllBytes(csrConfig.PathToCsr);
                var cert = await kvCertProvider.SigningRequestAsync(csr, estConfig.IssuingCA, 365);

                File.WriteAllBytes(csrConfig.OutputFileName, cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
                logger.LogInformation("Device certificate was created successfully.");
            }
        }
    }
}
