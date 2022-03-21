using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    public class KeyVaultCertificateProvider : IKeyVaultCertificateProvider
    {
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;

        public KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILogger<KeyVaultCertificateProvider> logger)
        {
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
        }

        public async Task CreateCACertificateAsync(string issuerCertificateName, string subject)
        {
            var certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(issuerCertificateName).ConfigureAwait(false);

            if (!certVersions.Any())
            {
                var notBefore = DateTime.UtcNow.AddDays(-1);
                await _keyVaultServiceClient.CreateCACertificateAsync(
                        issuerCertificateName,
                        subject,
                        notBefore,
                        notBefore.AddMonths(48), 
                        4096, 
                        256);
            }
        }

        public async Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName)
        {
            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);
            return new X509Certificate2(certBundle.Cer);
        }

        public async Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames)
        {
            _logger.LogDebug("Call GetPublicCertificatesByName method with following certificate names");
            var certs = new List<X509Certificate2>();

            foreach (var issuerName in certNames)
            {
                _logger.LogDebug("Certificate issuer name: {name}", issuerName);
                var cert = await GetCertificateAsync(issuerName).ConfigureAwait(false);

                if (cert != null)
                {
                    certs.Add(cert);
                }
            }

            return certs;
        }

        /// <summary>
        /// Creates a KeyVault signed certficate from signing request.
        /// </summary>
        public async Task<X509Certificate2> SigningRequestAsync(
            byte[] certificateRequest, 
            string issuerCertificateName, 
            int validityInDays,
            bool caCert = false)
        {
            _logger.LogInformation("Preparing certificate request with {name} issuer name, {days} days validity period and is a CA certificate flag set to {flag} ", issuerCertificateName, validityInDays, caCert);

            _logger.LogDebug("The content of the certificate request is: {content} ", certificateRequest.ToString());

            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(certificateRequest);

            if (!pkcs10CertificationRequest.Verify())
            {
                throw new ArgumentException("CSR signature invalid.");
            }

            var info = pkcs10CertificationRequest.GetCertificationRequestInfo();

            _logger.LogDebug("Certification request info is:  {info}", info.ToString());

            var notBefore = DateTime.UtcNow.AddDays(-1);

            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);

            var signingCert = new X509Certificate2(certBundle.Cer);
            var publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);

            return await KeyVaultCertFactory.CreateSignedCertificate(
                info.Subject.ToString(),
                2048,
                notBefore,
                notBefore.AddDays(validityInDays),
                256,
                signingCert,
                publicKey,
                new KeyVaultSignatureGenerator(_keyVaultServiceClient, certBundle.KeyIdentifier.Identifier, signingCert),
                caCert
                );
        }
    }
}