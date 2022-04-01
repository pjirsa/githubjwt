using System;
using System.IO;
using Azure.Security.KeyVault.Secrets;

namespace GitHubJwt
{
    public class KeyVaultPrivateKeySource : IPrivateKeySource
    {
        protected readonly Uri _secretUri;
        protected readonly SecretClient _client;

        public KeyVaultPrivateKeySource(string secretUri, SecretClient client)
        {
            if (string.IsNullOrEmpty(secretUri))
            {
                throw new ArgumentNullException(nameof(secretUri));
            }
            _secretUri = new Uri(secretUri);
            _client = client;
        }

        public TextReader GetPrivateKeyReader()
        {
            var secretId = new KeyVaultSecretIdentifier(_secretUri);
            var secret = _client.GetSecret(secretId.Name, secretId.Version);
            return new StringReader(secret.Value.Value.HydrateRsaVariable());
        }
    }
}