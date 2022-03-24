using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultCA
{
    public class CsrConfiguration
    {
        public bool IsRootCA { get; set; }

        public string PathToCsr { get; set; }

        public string OutputFileName { get; set; }
    }
}
