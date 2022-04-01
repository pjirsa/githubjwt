using System;
using System.IO;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System.Threading;
using SilverGiggle;

namespace GitHubJwt.Tests
{
    [TestClass]
    public class GitHubJwtFactoryTests
    {

        [TestMethod]
        public void CreateEncodedJwtToken_FromFileSource_ShouldNotFail()
        {
            // Arrange
            var privateKeySource = new FilePrivateKeySource("private.pem");
            var options = new GitHubJwtFactoryOptions
            {
                AppIntegrationId = 6837,
                ExpirationSeconds = 600 // 10 minutes maximum
            };
            var factory = new GitHubJwtFactory(privateKeySource, options);

            // Act
            var token = factory.CreateEncodedJwtToken();

            // Assert
            Assert.IsNotNull(token);
            Console.WriteLine(token);
        }

        [TestMethod]
        public void CreateEncodedJwtToken_FromEnvVar_ShouldNotFail()
        {
            // Arrange
            var privateKeyName = Guid.NewGuid().ToString("N");
            var privateKeySource = new EnvironmentVariablePrivateKeySource(privateKeyName);
            var options = new GitHubJwtFactoryOptions
            {
                AppIntegrationId = 6837,
                ExpirationSeconds = 600 // 10 minutes maximum
            };
            var factory = new GitHubJwtFactory(privateKeySource, options);

            using (new EnvironmentVariableScope(privateKeyName))
            {
                Environment.SetEnvironmentVariable(privateKeyName, File.ReadAllText("envvar.pem"));

                // Act
                var token = factory.CreateEncodedJwtToken();

                // Assert
                Assert.IsNotNull(token);
                Console.WriteLine(token);
            }
        }

        [TestMethod]
        public void CreateEncodedJwtToken_FromString_ShouldNotFail()
        {
            // Arrange
            var privateKeySource = new StringPrivateKeySource(File.ReadAllText("envvar.pem"));
            var options = new GitHubJwtFactoryOptions
            {
                AppIntegrationId = 6837,
                ExpirationSeconds = 600 // 10 minutes maximum
            };
            var factory = new GitHubJwtFactory(privateKeySource, options);

            // Act
            var token = factory.CreateEncodedJwtToken();

            // Assert
            Assert.IsNotNull(token);
            Console.WriteLine(token);
        }

        [TestMethod]
        public void CreateEncodedJwtToken_FromKeyVault_ShouldNotFail()
        {
            // Arrange
            var secret = new KeyVaultSecret("my-secret", File.ReadAllText("envvar.pem"));

            Response<KeyVaultSecret> response = Response.FromValue(secret, Mock.Of<Response>());

            Mock<SecretClient> clientMock = new Mock<SecretClient>();
            clientMock.Setup(c => c.GetSecret(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(response);

            SecretClient secretClient = clientMock.Object;

            var privateKeySource = new KeyVaultPrivateKeySource("https://myvault.vault.azure.net/secrets/my-secret/version", secretClient);
            var options = new GitHubJwtFactoryOptions
            {
                AppIntegrationId = 1234,
                ExpirationSeconds = 600 // 10 minutes maximum
            };
            var factory = new GitHubJwtFactory(privateKeySource, options);

            // Act
            var token = factory.CreateEncodedJwtToken();

            // Assert
            Assert.IsNotNull(token);
            Console.WriteLine(token);
        }

    }
}
