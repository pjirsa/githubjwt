using System;
using System.IO;
using Azure.Security.KeyVault.Secrets;

namespace GitHubJwt
{
    public class KeyVaultPrivateKeySource : IPrivateKeySource
    {
        protected readonly Uri _secretUri;
        protected readonly SecretClient _client;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultPrivateKeySource"/> class.
        /// </summary>
        /// <param name="secretUri">The secret URI. (https://myvault.vault.azure.net/secrets/my-secret/version)</param>
        /// <param name="client">The secret client. <see cref="SecretClient"/></param>
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