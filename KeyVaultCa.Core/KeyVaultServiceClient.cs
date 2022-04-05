using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    /// <summary>
    /// The KeyVault service client.
    /// </summary>
    public class KeyVaultServiceClient
    {
        private CertificateClient _keyVaultClient;
        private readonly ILogger _logger;
        public DefaultAzureCredential Credential { get; set; }

        /// <summary>
        /// Create the service client for KeyVault, with user or service credentials.
        /// </summary>
        /// <param name="vaultBaseUrl">The Url of the Key Vault.</param>
        public KeyVaultServiceClient(EstConfiguration config, DefaultAzureCredential credential, ILogger<KeyVaultServiceClient> logger)
        {
            _keyVaultClient = new CertificateClient(new Uri(config.KeyVaultUrl), credential);
            _logger = logger;
            Credential = credential;
        }

        public async Task<X509Certificate2> CreateCACertificateAsync(
                string id,
                string subject,
                DateTime notBefore,
                DateTime notAfter,
                int keySize,
                int hashSize,
                CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", id);
                var op = await _keyVaultClient.GetCertificateOperationAsync(id);
                await op.DeleteAsync();
            }
            catch
            {
                // intentionally ignore errors 
            }

            string caTempCertIdentifier = null;

            try
            {
                // create policy for self signed certificate with a new key
                var policySelfSignedNewKey = CreateCertificatePolicy(subject, keySize, true, false);

                var newCertificateOperation = await _keyVaultClient.StartCreateCertificateAsync(id, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", id);

                var createdCertificateBundle = await _keyVaultClient.GetCertificateAsync(id).ConfigureAwait(false);
                caTempCertIdentifier = createdCertificateBundle.Value.Id.ToString();

                _logger.LogDebug("Temporary certificate identifier is {certIdentifier}.", caTempCertIdentifier);
                _logger.LogDebug("Temporary certificate backing key identifier is {key}.", createdCertificateBundle.Value.KeyId);

                // create policy for unknown issuer and reuse key
                var policyUnknownReuse = CreateCertificatePolicy(subject, keySize, false, true);
                var tags = CreateCertificateTags(id, false);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                var createResult = await _keyVaultClient.StartCreateCertificateAsync(id, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                var pkcs10CertificationRequest = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(createResult.Properties.Csr);
                var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }

                // create the self signed root CA certificate
                _logger.LogDebug("Create the self signed root CA certificate.");
                var publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                var signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                    subject,
                    (ushort)keySize,
                    notBefore,
                    notAfter,
                    (ushort)hashSize,
                    null,
                    publicKey,
                    new KeyVaultSignatureGenerator(Credential, createdCertificateBundle.Value.KeyId, null),
                    true);

                // merge Root CA cert with the signed certificate
                _logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                MergeCertificateOptions options = new MergeCertificateOptions(id, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                var mergeResult = await _keyVaultClient.MergeCertificateAsync(options);

                return signedcert;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new Root CA certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse = _keyVaultClient.GetCertificate(caTempCertIdentifier);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _keyVaultClient.UpdateCertificatePropertiesAsync(certificateProperties);
                    }
                    catch
                    {
                        // intentionally ignore error
                    }
                }
            }
        }

        private Dictionary<string, string> CreateCertificateTags(string id, bool trusted)
        {
            var tags = new Dictionary<string, string>
            {
                [id] = trusted ? "Trusted" : "Issuer"
            };

            _logger.LogDebug("Created certificate tags for certificate with id {id} and trusted {trusted}.", id, trusted);
            return tags;
        }

        private CertificatePolicy CreateCertificatePolicy(
            string subject,
            int keySize,
            bool selfSigned,
            bool reuseKey = false,
            bool exportable = false)
        {
            var issuerName = selfSigned ? "Self" : "Unknown";
            var policy = new CertificatePolicy(issuerName, subject)
            {
                Exportable = exportable,
                KeySize = keySize,
                KeyType = "RSA",
                ReuseKey = reuseKey,
                ContentType = CertificateContentType.Pkcs12
            };

            _logger.LogDebug("Created certificate policy for certificate with issuer name {issuerName}, self signed {selfSigned} and reused key {reuseKey}.", issuerName, selfSigned, reuseKey);
            return policy;
        }

        /// <summary>
        /// Get Certificate with Policy from Key Vault.
        /// </summary>
        /// <param name="name">Key Vault name</param>
        /// <param name="ct">CancellationToken</param>
        /// <returns></returns>

        internal async Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string name, CancellationToken ct = default)
        {
            return await _keyVaultClient.GetCertificateAsync(name, ct).ConfigureAwait(false);
        }

        internal async Task<int> GetCertificateVersionsAsync(string name)
        {
            var versions = 0;
            await foreach (CertificateProperties cert in _keyVaultClient.GetPropertiesOfCertificateVersionsAsync(name))
            {
                versions++;
            }
            return versions;
        }
    }
}

