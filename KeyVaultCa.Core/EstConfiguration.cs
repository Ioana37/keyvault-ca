using System;

namespace KeyVaultCa.Core
{
    public enum AuthMode
    {
        Basic = 0,
        x509 = 1
    }

    public class EstConfiguration
    {
        public string Subject { get; set; }

        public string KeyVaultUrl { get; set; }

        public string AppId { get; set; }

        public string Secret { get; set; }

        public string IssuingCA { get; set; }

        public string EstUsername { get; set; }

        public string EstPassword { get; set; }

        public int CertValidityInDays { get; set; }

        public string Auth { get; set; }

        public AuthMode AuthMode => (AuthMode)Enum.Parse(typeof(AuthMode), Auth);
    }
}
