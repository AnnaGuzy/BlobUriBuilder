using System;

using Azure.Storage.Blobs;

namespace ConsoleApp4
{
    class Program
    {
        static void Main(string[] args)
        {
            // our case right now, doesn't work, account name is empty
            // mommyvm.westus.cloudapp.azure.com is fqdn of my parent device
            var builder = new BlobUriBuilder(
                new Uri("https://mommyvm.westus.cloudapp.azure.com:443/factorypersisted/iiotcontainerlogs")){
                BlobName = "2021/07/07/FactoryEdgeLogging-2021-07-07-12-10-17-logs.gzip"
            };
            var uri = builder.ToUri();
            Console.WriteLine(uri);

            // this case creates valid url but because it uses IP instead of domain name, it results in CertificateNameMismatch
            // 104.42.122.116 is IP of my parent device
            builder = new BlobUriBuilder(
                new Uri("https://104.42.122.116:443/factorypersisted/iiotcontainerlogs")){
                BlobName = "2021/07/07/FactoryEdgeLogging-2021-07-07-12-10-17-logs.gzip"
            };
            uri = builder.ToUri();
            Console.WriteLine(uri);

            // this case creates valid url but it would require to change parent proxy port to 11002 from 443
            builder = new BlobUriBuilder(
                new Uri("https://mommyvm.westus.cloudapp.azure.com:11002/factorypersisted/iiotcontainerlogs")){
                BlobName = "2021/07/07/FactoryEdgeLogging-2021-07-07-12-10-17-logs.gzip"
            };
            uri = builder.ToUri();
            Console.WriteLine(uri);
        }
    }
}
