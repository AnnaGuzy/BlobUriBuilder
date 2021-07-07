using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using Azure.Core;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Sas;

using Microsoft.VisualBasic;

using static ConsoleApp4.Constants.File;
using static ConsoleApp4.Constants.Sas;

namespace ConsoleApp4
{
    /// <summary>
    /// The <see cref="Azure.Storage.Blobs.BlobUriBuilder"/> class provides a convenient way to
    /// modify the contents of a <see cref="System.Uri"/> instance to point to
    /// different Azure Storage resources like an account, container, or blob.
    ///
    /// For more information, see
    /// <see href="https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata">
    /// Naming and Referencing Containers, Blobs, and Metadata</see>.
    /// </summary>
    public class BlobUriBuilder
    {
        /// <summary>
        /// The Uri instance constructed by this builder.  It will be reset to
        /// null when changes are made and reconstructed when <see cref="Uri"/>
        /// is accessed.
        /// </summary>
        private Uri _uri;

        /// <summary>
        /// Whether the Uri is a path-style Uri (i.e. it is an IP Uri or the domain includes a port that is used by the local emulator).
        /// </summary>
        private readonly bool _isPathStyleUri;

        /// <summary>
        /// Gets or sets the scheme name of the URI.
        /// Example: "https"
        /// </summary>
        public string Scheme
        {
            get => _scheme;
            set
            {
                ResetUri();
                _scheme = value;
            }
        }

        private string _scheme;

        /// <summary>
        /// Gets or sets the Domain Name System (DNS) host name or IP address
        /// of a server.
        ///
        /// Example: "account.blob.core.windows.net"
        /// </summary>
        public string Host
        {
            get => _host;
            set
            {
                ResetUri();
                _host = value;
            }
        }

        private string _host;

        /// <summary>
        /// Gets or sets the port number of the URI.
        /// </summary>
        public int Port
        {
            get => _port;
            set
            {
                ResetUri();
                _port = value;
            }
        }

        private int _port;

        /// <summary>
        /// Gets or sets the Azure Storage account name.
        /// </summary>
        public string AccountName
        {
            get => _accountName;
            set
            {
                ResetUri();
                _accountName = value;
            }
        }

        private string _accountName;

        /// <summary>
        /// Gets or sets the name of a blob storage Container.  The value
        /// defaults to <see cref="String.Empty"/> if not present in the
        /// <see cref="System.Uri"/>.
        /// </summary>
        public string BlobContainerName
        {
            get => _containerName;
            set
            {
                ResetUri();
                _containerName = value;
            }
        }

        private string _containerName;

        /// <summary>
        /// Gets or sets the name of a blob.  The value defaults to
        /// <see cref="String.Empty"/> if not present in the <see cref="System.Uri"/>.
        /// </summary>
        public string BlobName
        {
            get => _blobName;
            set
            {
                ResetUri();
                _blobName = value;
            }
        }

        private string _blobName;

        /// <summary>
        /// Gets or sets the name of a blob snapshot.  The value defaults to
        /// <see cref="String.Empty"/> if not present in the <see cref="System.Uri"/>.
        /// </summary>
        public string Snapshot
        {
            get => _snapshot;
            set
            {
                ResetUri();
                _snapshot = value;
            }
        }

        private string _snapshot;

        /// <summary>
        /// Gets or sets the name of a blob version.  The value defaults to
        /// <see cref="string.Empty"/> if not present in the <see cref="System.Uri"/>.
        /// </summary>
        public string VersionId
        {
            get => _versionId;
            set
            {
                ResetUri();
                _versionId = value;
            }
        }

        private string _versionId;

        ///// <summary>
        ///// Gets or sets the VersionId.  The value defaults to
        ///// <see cref="String.Empty"/> if not present in the <see cref="Uri"/>.
        ///// </summary>
        //public string VersionId
        //{
        //    get => this._versionId;
        //    set { this.ResetUri(); this._versionId = value; }
        //}
        //private string _versionId;

        /// <summary>
        /// Gets or sets the Shared Access Signature query parameters, or null
        /// if not present in the <see cref="System.Uri"/>.
        /// </summary>
        public BlobSasQueryParameters Sas
        {
            get => _sas;
            set
            {
                ResetUri();
                _sas = value;
            }
        }

        private BlobSasQueryParameters _sas;

        /// <summary>
        /// Gets or sets any query information included in the URI that's not
        /// relevant to addressing Azure storage resources.
        /// </summary>
        public string Query
        {
            get => _query;
            set
            {
                ResetUri();
                _query = value;
            }
        }

        private string _query;

        /// <summary>
        /// Initializes a new instance of the <see cref="Azure.Storage.Blobs.BlobUriBuilder"/>
        /// class with the specified <see cref="System.Uri"/>.
        /// </summary>
        /// <param name="uri">
        /// The <see cref="System.Uri"/> to a storage resource.
        /// </param>
        public BlobUriBuilder(Uri uri)
        {
            uri = uri ?? throw new ArgumentNullException(nameof(uri));

            Scheme = uri.Scheme;
            Host = uri.Host;
            Port = uri.Port;

            AccountName = "";
            BlobContainerName = "";
            BlobName = "";

            Snapshot = "";
            VersionId = "";
            Sas = null;
            Query = "";

            // Find the account, container, & blob names (if any)
            if (!string.IsNullOrEmpty(uri.AbsolutePath))
            {
                var path = uri.GetPath();

                var startIndex = 0;

                if (uri.IsHostIPEndPointStyle())
                {
                    _isPathStyleUri = true;
                    var accountEndIndex = path.IndexOf("/", StringComparison.InvariantCulture);

                    // Slash not found; path has account name & no container name
                    if (accountEndIndex == -1)
                    {
                        AccountName = path;
                        startIndex = path.Length;
                    }
                    else
                    {
                        AccountName = path.Substring(0, accountEndIndex);
                        startIndex = accountEndIndex + 1;
                    }
                }
                else
                {
                    AccountName = uri.GetAccountNameFromDomain(Constants.Blob.UriSubDomain) ?? string.Empty;
                }

                // Find the next slash (if it exists)
                var containerEndIndex = path.IndexOf("/", startIndex, StringComparison.InvariantCulture);
                if (containerEndIndex == -1)
                {
                    BlobContainerName =
                        path.Substring(startIndex); // Slash not found; path has container name & no blob name
                }
                else
                {
                    BlobContainerName =
                        path.Substring(startIndex,
                            containerEndIndex - startIndex); // The container name is the part between the slashes
                    BlobName = path.Substring(containerEndIndex + 1)
                        .UnescapePath(); // The blob name is after the container slash
                }
            }

            // Convert the query parameters to a case-sensitive map & trim whitespace
            var paramsMap = new UriQueryParamsCollection(uri.Query);

            if (paramsMap.TryGetValue(Constants.SnapshotParameterName, out var snapshotTime))
            {
                Snapshot = snapshotTime;

                // If we recognized the query parameter, remove it from the map
                paramsMap.Remove(Constants.SnapshotParameterName);
            }

            if (paramsMap.TryGetValue(Constants.VersionIdParameterName, out var versionId))
            {
                VersionId = versionId;

                // If we recognized the query parameter, remove it from the map
                paramsMap.Remove(Constants.VersionIdParameterName);
            }

            if (!string.IsNullOrEmpty(Snapshot) && !string.IsNullOrEmpty(VersionId))
            {
                throw new ArgumentException("Snapshot and VersionId cannot both be set.");
            }

            if (paramsMap.ContainsKey(Constants.Sas.Parameters.Version))
            {
                Sas = new BlobSasQueryParameters(paramsMap);
            }

            Query = paramsMap.ToString();
        }

        /// <summary>
        /// Returns the <see cref="System.Uri"/> constructed from the
        /// <see cref="Azure.Storage.Blobs.BlobUriBuilder"/>'s fields. The <see cref="Uri.Query"/>
        /// property contains the SAS and additional query parameters.
        /// </summary>
        public Uri ToUri()
        {
            if (_uri == null)
            {
                _uri = BuildUri().ToUri();
            }

            return _uri;
        }

        /// <summary>
        /// Returns the display string for the specified
        /// <see cref="Azure.Storage.Blobs.BlobUriBuilder"/> instance.
        /// </summary>
        /// <returns>
        /// The display string for the specified <see cref="Azure.Storage.Blobs.BlobUriBuilder"/>
        /// instance.
        /// </returns>
        public override string ToString() =>
            BuildUri().ToString();

        /// <summary>
        /// Reset our cached URI.
        /// </summary>
        private void ResetUri() =>
            _uri = null;

        /// <summary>
        /// Construct a <see cref="RequestUriBuilder"/> representing the
        /// <see cref="Azure.Storage.Blobs.BlobUriBuilder"/>'s fields. The <see cref="Uri.Query"/>
        /// property contains the SAS, snapshot, and unparsed query parameters.
        /// </summary>
        /// <returns>The constructed <see cref="RequestUriBuilder"/>.</returns>
        private RequestUriBuilder BuildUri()
        {
            // Concatenate account, container, & blob names (if they exist)
            var path = new StringBuilder("");
            // only append the account name to the path for Ip style Uri.
            // regular style Uri will already have account name in domain
            if (_isPathStyleUri && !string.IsNullOrWhiteSpace(AccountName))
            {
                path.Append('/').Append(AccountName);
            }

            if (!string.IsNullOrWhiteSpace(BlobContainerName))
            {
                path.Append('/').Append(BlobContainerName);
                if (BlobName != null && BlobName.Length > 0)
                {
                    path.Append('/').Append(Uri.EscapeDataString(BlobName));
                }
            }

            // Concatenate query parameters
            var query = new StringBuilder(Query);
            if (!string.IsNullOrWhiteSpace(Snapshot))
            {
                if (query.Length > 0)
                {
                    query.Append('&');
                }

                query.Append(Constants.SnapshotParameterName).Append('=').Append(Snapshot);
            }

            if (!string.IsNullOrWhiteSpace(VersionId))
            {
                if (query.Length > 0)
                {
                    query.Append('&');
                }

                query.Append(Constants.VersionIdParameterName).Append('=').Append(VersionId);
            }

            var sas = Sas?.ToString();
            if (!string.IsNullOrWhiteSpace(sas))
            {
                if (query.Length > 0)
                {
                    query.Append('&');
                }

                query.Append(sas);
            }

            // Use RequestUriBuilder, which has slightly nicer formatting
            return new RequestUriBuilder
            {
                Scheme = Scheme,
                Host = Host,
                Port = Port,
                Path = path.ToString(),
                Query = query.Length > 0 ? "?" + query.ToString() : null
            };
        }
    }
    /// <summary>
    /// Extension methods used to manipulate URIs.
    /// </summary>
    internal static class UriExtensions
    {
        /// <summary>
        /// Append a segment to a URIs path.
        /// </summary>
        /// <param name="uri">The URI.</param>
        /// <param name="segment">The relative segment to append.</param>
        /// <returns>The combined URI.</returns>
        public static Uri AppendToPath(this Uri uri, string segment)
        {
            var builder = new UriBuilder(uri);
            var path = builder.Path;
            var seperator = (path.Length == 0 || path[path.Length - 1] != '/') ? "/" : "";
            // In URLs, the percent sign is used to encode special characters, so if the segment
            // has a percent sign in their URL path, we have to encode it before adding it to the path
            segment = segment.Replace(Constants.PercentSign, Constants.EncodedPercentSign);
            builder.Path += seperator + segment;
            return builder.Uri;
        }

        /// <summary>
        /// Get the (already encoded) query parameters on a URI.
        /// </summary>
        /// <param name="uri">The URI.</param>
        /// <returns>Dictionary mapping query parameters to values.</returns>
        public static IDictionary<string, string> GetQueryParameters(this Uri uri)
        {
            var parameters = new Dictionary<string, string>();
            var query = uri.Query ?? "";
            if (!string.IsNullOrEmpty(query))
            {
                if (query.StartsWith("?", true, CultureInfo.InvariantCulture))
                {
                    query = query.Substring(1);
                }
                foreach (var param in query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = param.Split(new[] { '=' }, 2);
                    var name = WebUtility.UrlDecode(parts[0]);
                    if (parts.Length == 1)
                    {
                        parameters.Add(name, default);
                    }
                    else
                    {
                        parameters.Add(name, WebUtility.UrlDecode(parts[1]));
                    }
                }
            }
            return parameters;
        }

        /// <summary>
        /// Get the account name from the domain portion of a Uri.
        /// </summary>
        /// <param name="uri">The Uri.</param>
        /// <param name="serviceSubDomain">The service subdomain used to validate that the
        /// domain is in the expected format. This should be "blob" for blobs, "file" for files,
        /// "queue" for queues, "blob" and "dfs" for datalake.</param>
        /// <returns>Account name or null if not able to be parsed.</returns>
        public static string GetAccountNameFromDomain(this Uri uri, string serviceSubDomain) =>
            GetAccountNameFromDomain(uri.Host, serviceSubDomain);

        /// <summary>
        /// Get the account name from the host.
        /// </summary>
        /// <param name="host">Host.</param>
        /// <param name="serviceSubDomain">The service subdomain used to validate that the
        /// domain is in the expected format. This should be "blob" for blobs, "file" for files,
        /// "queue" for queues, "blob" and "dfs" for datalake.</param>
        /// <returns>Account name or null if not able to be parsed.</returns>
        public static string GetAccountNameFromDomain(string host, string serviceSubDomain)
        {
            var accountEndIndex = host.IndexOf(".", StringComparison.InvariantCulture);
            if (accountEndIndex >= 0)
            {
                var serviceStartIndex = accountEndIndex + 1;
                var serviceEndIndex = host.IndexOf(".", serviceStartIndex, StringComparison.InvariantCulture);
                if (serviceEndIndex > serviceStartIndex)
                {
                    var service = host.Substring(serviceStartIndex, serviceEndIndex - serviceStartIndex);
                    if (service == serviceSubDomain)
                    {
                        return host.Substring(0, accountEndIndex);
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// If path starts with a slash, remove it
        /// </summary>
        /// <param name="uri">The Uri.</param>
        /// <returns>Sanitized Uri.</returns>
        public static string GetPath(this Uri uri) =>
            (uri.AbsolutePath[0] == '/') ?
                uri.AbsolutePath.Substring(1) :
                uri.AbsolutePath;

        // See remarks at https://docs.microsoft.com/en-us/dotnet/api/system.net.ipaddress.tryparse?view=netframework-4.7.2
        /// <summary>
        /// Check to see if Uri is using IP Endpoint style.
        /// </summary>
        /// <param name="uri">The Uri.</param>
        /// <returns>True if using IP Endpoint style.</returns>
        public static bool IsHostIPEndPointStyle(this Uri uri)
        {
            return (!string.IsNullOrEmpty(uri.Host) &&
                    uri.Host.IndexOf(".", StringComparison.InvariantCulture) >= 0 &&
                    IPAddress.TryParse(uri.Host, out _)) ||
                   Constants.Sas.PathStylePorts.Contains(uri.Port);
        }

        /// <summary>
        /// Appends a query parameter to the string builder.
        /// </summary>
        /// <param name="sb">string builder instance.</param>
        /// <param name="key">query parameter key.</param>
        /// <param name="value">query parameter value.</param>
        internal static void AppendQueryParameter(this StringBuilder sb, string key, string value) =>
            sb
            .Append(sb.Length > 0 ? "&" : "")
            .Append(key)
            .Append('=')
            .Append(value);
    }
    internal static class Constants
    {
        public const int KB = 1024;
        public const int MB = KB * 1024;
        public const int GB = MB * 1024;
        public const long TB = GB * 1024L;
        public const int Base16 = 16;

        public const int MaxReliabilityRetries = 5;

        /// <summary>
        /// The maximum allowed time between read or write calls to the stream for IdleCancellingStream.
        /// </summary>
        public const int MaxIdleTimeMs = 120000;

        /// <summary>
        /// Gets the default service version to use when building shared access
        /// signatures.
        /// </summary>
        public const string DefaultSasVersion = "2020-04-08";

        /// <summary>
        /// The default size of staged blocks when uploading small blobs.
        /// </summary>
        public const int DefaultBufferSize = 4 * Constants.MB;

        /// <summary>
        /// The size of staged blocks when uploading large blobs.
        /// </summary>
        public const int LargeBufferSize = 8 * Constants.MB;

        /// <summary>
        /// The threshold where we switch from staging <see cref="DefaultBufferSize"/>
        /// buffers to staging <see cref="LargeBufferSize"/> buffers.
        /// </summary>
        public const int LargeUploadThreshold = 100 * Constants.MB;

        /// <summary>
        /// The minimum number of bytes to download in Open Read.
        /// </summary>
        public const int DefaultStreamingDownloadSize = 4 * Constants.MB;

        /// <summary>
        /// Different .NET implementations have different default sizes for <see cref="System.IO.Stream.CopyTo(System.IO.Stream)"/>
        /// and it's overloads. This is the default for .NET Core to be applied everywhere for test consistency.
        /// </summary>
        public const int DefaultStreamCopyBufferSize = 81920;

        /// <summary>
        /// The size of the buffer to use when copying streams during a
        /// download operation.
        /// </summary>
        public const int DefaultDownloadCopyBufferSize = 16384;

        public const string CloseAllHandles = "*";
        public const string Wildcard = "*";

        /// <summary>
        /// The default format we use for block names.  There are 50,000
        /// maximum blocks so we pad the size with up to 4 leading zeros.
        /// </summary>
        public const string BlockNameFormat = "Block_{0:D5}";

        // SASTimeFormat represents the format of a SAS start or expiry time. Use it when formatting/parsing a time.Time.
        // ISO 8601 uses "yyyy'-'MM'-'dd'T'HH':'mm':'ss"
        public const string SasTimeFormatSeconds = "yyyy-MM-ddTHH:mm:ssZ";
        public const string SasTimeFormatSubSeconds = "yyyy-MM-ddTHH:mm:ss.fffffffZ";
        public const string SasTimeFormatMinutes = "yyyy-MM-ddTHH:mmZ";
        public const string SasTimeFormatDays = "yyyy-MM-dd";

        public const string SnapshotParameterName = "snapshot";
        public const string VersionIdParameterName = "versionid";
        public const string ShareSnapshotParameterName = "sharesnapshot";

        public const string Https = "https";
        public const string Http = "http";

        public const string PercentSign = "%";
        public const string EncodedPercentSign = "%25";

        public const string FalseName = "false";
        public const string TrueName = "true";

        /// <summary>
        /// Storage Connection String constant values.
        /// </summary>
        internal static class ConnectionStrings
        {
            /// <summary>
            /// The default port numbers for development storage credentials
            /// </summary>
            internal const int BlobEndpointPortNumber = 10000;
            internal const int QueueEndpointPortNumber = 10001;
            internal const int TableEndpointPortNumber = 10002;

            internal const string UseDevelopmentSetting = "UseDevelopmentStorage";
            internal const string DevelopmentProxyUriSetting = "DevelopmentStorageProxyUri";
            internal const string DefaultEndpointsProtocolSetting = "DefaultEndpointsProtocol";
            internal const string AccountNameSetting = "AccountName";
            internal const string AccountKeyNameSetting = "AccountKeyName";
            internal const string AccountKeySetting = "AccountKey";
            internal const string BlobEndpointSetting = "BlobEndpoint";
            internal const string QueueEndpointSetting = "QueueEndpoint";
            internal const string TableEndpointSetting = "TableEndpoint";
            internal const string FileEndpointSetting = "FileEndpoint";
            internal const string BlobSecondaryEndpointSetting = "BlobSecondaryEndpoint";
            internal const string QueueSecondaryEndpointSetting = "QueueSecondaryEndpoint";
            internal const string TableSecondaryEndpointSetting = "TableSecondaryEndpoint";
            internal const string FileSecondaryEndpointSetting = "FileSecondaryEndpoint";
            internal const string EndpointSuffixSetting = "EndpointSuffix";
            internal const string SharedAccessSignatureSetting = "SharedAccessSignature";
            internal const string DevStoreAccountName = "devstoreaccount1";
            internal const string DevStoreAccountKey =
                "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
            internal const string SecondaryLocationAccountSuffix = "-secondary";
            internal const string DefaultEndpointSuffix = "core.windows.net";
            internal const string DefaultBlobHostnamePrefix = "blob";
            internal const string DefaultQueueHostnamePrefix = "queue";
            internal const string DefaultTableHostnamePrefix = "table";
            internal const string DefaultFileHostnamePrefix = "file";
        }

        /// <summary>
        /// Header Name constant values.
        /// </summary>
        internal static class HeaderNames
        {
            public const string XMsPrefix = "x-ms-";
            public const string MetadataPrefix = "x-ms-meta-";
            public const string ErrorCode = "x-ms-error-code";
            public const string RequestId = "x-ms-request-id";
            public const string ClientRequestId = "x-ms-client-request-id";
            public const string Date = "x-ms-date";
            public const string SharedKey = "SharedKey";
            public const string Authorization = "Authorization";
            public const string ContentEncoding = "Content-Encoding";
            public const string ContentLanguage = "Content-Language";
            public const string ContentLength = "Content-Length";
            public const string ContentMD5 = "Content-MD5";
            public const string ContentType = "Content-Type";
            public const string IfModifiedSince = "If-Modified-Since";
            public const string IfMatch = "If-Match";
            public const string IfNoneMatch = "If-None-Match";
            public const string IfUnmodifiedSince = "If-Unmodified-Since";
            public const string Range = "Range";
            public const string ContentRange = "Content-Range";
            public const string VersionId = "x-ms-version-id";
        }

        internal static class ErrorCodes
        {
            public const string InternalError = "InternalError";
            public const string OperationTimedOut = "OperationTimedOut";
            public const string ServerBusy = "ServerBusy";
        }

        /// <summary>
        /// Blob constant values.
        /// </summary>
        internal static class Blob
        {
            public const int HttpsPort = 443;
            public const string UriSubDomain = "blob";
            public const int QuickQueryDownloadSize = 4 * Constants.MB;

            internal static class Append
            {
                public const int MaxAppendBlockBytes = 4 * Constants.MB; // 4MB
                public const int MaxBlocks = 50000;
            }

            internal static class Block
            {
                public const int DefaultConcurrentTransfersCount = 5;
                public const int DefaultInitalDownloadRangeSize = 256 * Constants.MB; // 256 MB
                public const int Pre_2019_12_12_MaxUploadBytes = 256 * Constants.MB; // 256 MB
                public const long MaxUploadBytes = 5000L * Constants.MB; // 5000MB
                public const int MaxDownloadBytes = 256 * Constants.MB; // 256MB
                public const int Pre_2019_12_12_MaxStageBytes = 100 * Constants.MB; // 100 MB
                public const long MaxStageBytes = 4000L * Constants.MB; // 4000MB
                public const int MaxBlocks = 50000;
            }

            internal static class Page
            {
                public const int PageSizeBytes = 512;
            }

            internal static class Container
            {
                public const string Name = "Blob Container";
                /// <summary>
                /// The Azure Storage name used to identify a storage account's root container.
                /// </summary>
                public const string RootName = "$root";

                /// <summary>
                /// The Azure Storage name used to identify a storage account's logs container.
                /// </summary>
                public const string LogsName = "$logs";

                /// <summary>
                /// The Azure Storage name used to identify a storage account's web content container.
                /// </summary>
                public const string WebName = "$web";
            }

            internal static class Lease
            {
                /// <summary>
                /// Lease Duration is set as infinite when passed -1.
                /// </summary>
                public const int InfiniteLeaseDuration = -1;
            }
        }

        /// <summary>
        /// File constant values.
        /// </summary>
        internal static class File
        {
            public const string UriSubDomain = "file";
            public const string FileAttributesNone = "None";
            public const string FileTimeNow = "Now";
            public const string Preserve = "Preserve";
            public const string FilePermissionInherit = "Inherit";
            public const int MaxFilePermissionHeaderSize = 8 * KB;
            public const int MaxFileUpdateRange = 4 * MB;
            public const string FileTimeFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffff'Z'";
            public const string SnapshotParameterName = "sharesnapshot";

            public const string SmbProtocol = "SMB";
            public const string NfsProtocol = "NFS";

            internal static class Lease
            {
                /// <summary>
                /// Lease Duration is set as infinite when passed -1.
                /// </summary>
                public const long InfiniteLeaseDuration = -1;
            }

            internal static class Errors
            {
                public const string ShareUsageBytesOverflow =
                    "ShareUsageBytes exceeds int.MaxValue. Use ShareUsageInBytes instead.";

                public const string LeaseNotPresentWithFileOperation =
                    "LeaseNotPresentWithFileOperation";
            }

            internal static class Share
            {
                public const string Name = "Share";
            }
        }

        /// <summary>
        /// Data Lake constant values.
        /// </summary>
        internal static class DataLake
        {
            /// <summary>
            /// The blob URI suffix.
            /// </summary>
            public const string BlobUriSuffix = Blob.UriSubDomain;

            /// <summary>
            /// The DFS URI suffix.
            /// </summary>
            public const string DfsUriSuffix = "dfs";

            /// <summary>
            /// The key of the object json object returned for errors.
            /// </summary>
            public const string ErrorKey = "error";

            /// <summary>
            /// The key of the error code returned for errors.
            /// </summary>
            public const string ErrorCodeKey = "code";

            /// <summary>
            /// The key of the error message returned for errors.
            /// </summary>
            public const string ErrorMessageKey = "message";

            /// <summary>
            /// The Azure Storage error codes for Datalake Client.
            /// </summary>
            public const string AlreadyExists = "ContainerAlreadyExists";
            public const string FilesystemNotFound = "FilesystemNotFound";
            public const string PathNotFound = "PathNotFound";

            /// <summary>
            /// Default concurrent transfers count.
            /// </summary>
            public const int DefaultConcurrentTransfersCount = 5;

            /// <summary>
            /// Max upload bytes for less than Service Version 2019-12-12.
            /// </summary>
            public const int Pre_2019_12_12_MaxAppendBytes = 100 * Constants.MB; // 100 MB

            /// <summary>
            /// Max upload bytes.
            /// </summary>
            public const long MaxAppendBytes = 4000L * Constants.MB; // 4000MB;

            /// <summary>
            /// Metadata key for isFolder property.
            /// </summary>
            public const string IsDirectoryKey = "hdi_isFolder";

            public const string FileSystemName = "FileSystem";
        }

        /// <summary>
        /// Queue constant values.
        /// </summary>
        internal static class Queue
        {
            /// <summary>
            /// QueueMaxMessagesDequeue indicates the maximum number of messages
            /// you can retrieve with each call to Dequeue.
            /// </summary>
            public const int MaxMessagesDequeue = 32;

            /// <summary>
            /// QueueMessageMaxBytes indicates the maximum number of bytes allowed for a message's UTF-8 text.
            /// </summary>
            public const int QueueMessageMaxBytes = 64 * Constants.KB;

            public const int StatusCodeNoContent = 204;

            public const string MessagesUri = "messages";

            public const string UriSubDomain = "queue";
        }

        /// <summary>
        /// ChangeFeed constant values.
        /// </summary>
        internal static class ChangeFeed
        {
            public const string ChangeFeedContainerName = "$blobchangefeed";
            public const string SegmentPrefix = "idx/segments/";
            public const string InitalizationManifestPath = "/0000/";
            public const string InitalizationSegment = "1601";
            public const string MetaSegmentsPath = "meta/segments.json";
            public const long ChunkBlockDownloadSize = MB;
            public const int DefaultPageSize = 5000;
            public const int LazyLoadingBlobStreamBlockSize = 3 * Constants.KB;

            internal static class Event
            {
                public const string Topic = "topic";
                public const string Subject = "subject";
                public const string EventType = "eventType";
                public const string EventTime = "eventTime";
                public const string EventId = "id";
                public const string Data = "data";
                public const string SchemaVersion = "schemaVersion";
                public const string MetadataVersion = "metadataVersion";
            }

            internal static class EventData
            {
                public const string Api = "api";
                public const string ClientRequestId = "clientRequestId";
                public const string RequestId = "requestId";
                public const string Etag = "etag";
                public const string ContentType = "contentType";
                public const string ContentLength = "contentLength";
                public const string BlobType = "blobType";
                public const string BlockBlob = "BlockBlob";
                public const string PageBlob = "pageBlob";
                public const string AppendBlob = "AppendBlob";
                public const string ContentOffset = "contentOffset";
                public const string DestinationUrl = "destinationUrl";
                public const string SourceUrl = "sourceUrl";
                public const string Url = "url";
                public const string Recursive = "recursive";
                public const string Sequencer = "sequencer";
            }
        }

        /// <summary>
        /// Quick Query constant values.
        /// </summary>
        internal static class QuickQuery
        {
            public const string SqlQueryType = "SQL";

            public const string Data = "data";
            public const string BytesScanned = "bytesScanned";
            public const string TotalBytes = "totalBytes";
            public const string Fatal = "fatal";
            public const string Name = "name";
            public const string Description = "description";
            public const string Position = "position";

            public const string DataRecordName = "com.microsoft.azure.storage.queryBlobContents.resultData";
            public const string ProgressRecordName = "com.microsoft.azure.storage.queryBlobContents.progress";
            public const string ErrorRecordName = "com.microsoft.azure.storage.queryBlobContents.error";
            public const string EndRecordName = "com.microsoft.azure.storage.queryBlobContents.end";

            public const string ArrowFieldTypeInt64 = "int64";
            public const string ArrowFieldTypeBool = "bool";
            public const string ArrowFieldTypeTimestamp = "timestamp[ms]";
            public const string ArrowFieldTypeString = "string";
            public const string ArrowFieldTypeDouble = "double";
            public const string ArrowFieldTypeDecimal = "decimal";
        }

        /// <summary>
        /// Sas constant values.
        /// </summary>
        internal static class Sas
        {
            internal static class Permissions
            {
                public const char Read = 'r';
                public const char Write = 'w';
                public const char Delete = 'd';
                public const char DeleteBlobVersion = 'x';
                public const char List = 'l';
                public const char Add = 'a';
                public const char Update = 'u';
                public const char Process = 'p';
                public const char Create = 'c';
                public const char Tag = 't';
                public const char FilterByTags = 'f';
                public const char Move = 'm';
                public const char Execute = 'e';
                public const char ManageOwnership = 'o';
                public const char ManageAccessControl = 'p';
            }

            internal static class Parameters
            {
                public const string Version = "sv";
                public const string VersionUpper = "SV";
                public const string Services = "ss";
                public const string ServicesUpper = "SS";
                public const string ResourceTypes = "srt";
                public const string ResourceTypesUpper = "SRT";
                public const string Protocol = "spr";
                public const string ProtocolUpper = "SPR";
                public const string StartTime = "st";
                public const string StartTimeUpper = "ST";
                public const string ExpiryTime = "se";
                public const string ExpiryTimeUpper = "SE";
                public const string IPRange = "sip";
                public const string IPRangeUpper = "SIP";
                public const string Identifier = "si";
                public const string IdentifierUpper = "SI";
                public const string Resource = "sr";
                public const string ResourceUpper = "SR";
                public const string Permissions = "sp";
                public const string PermissionsUpper = "SP";
                public const string Signature = "sig";
                public const string SignatureUpper = "SIG";
                public const string KeyObjectId = "skoid";
                public const string KeyObjectIdUpper = "SKOID";
                public const string KeyTenantId = "sktid";
                public const string KeyTenantIdUpper = "SKTID";
                public const string KeyStart = "skt";
                public const string KeyStartUpper = "SKT";
                public const string KeyExpiry = "ske";
                public const string KeyExpiryUpper = "SKE";
                public const string KeyService = "sks";
                public const string KeyServiceUpper = "SKS";
                public const string KeyVersion = "skv";
                public const string KeyVersionUpper = "SKV";
                public const string CacheControl = "rscc";
                public const string CacheControlUpper = "RSCC";
                public const string ContentDisposition = "rscd";
                public const string ContentDispositionUpper = "RSCD";
                public const string ContentEncoding = "rsce";
                public const string ContentEncodingUpper = "RSCE";
                public const string ContentLanguage = "rscl";
                public const string ContentLanguageUpper = "RSCL";
                public const string ContentType = "rsct";
                public const string ContentTypeUpper = "RSCT";
                public const string PreauthorizedAgentObjectId = "saoid";
                public const string PreauthorizedAgentObjectIdUpper = "SAOID";
                public const string AgentObjectId = "suoid";
                public const string AgentObjectIdUpper = "SUOID";
                public const string CorrelationId = "scid";
                public const string CorrelationIdUpper = "SCID";
                public const string DirectoryDepth = "sdd";
                public const string DirectoryDepthUpper = "SDD";
            }

            internal static class Resource
            {
                public const string BlobSnapshot = "bs";
                public const string BlobVersion = "bv";
                public const string Blob = "b";
                public const string Container = "c";
                public const string File = "f";
                public const string Share = "s";
                public const string Directory = "d";
            }

            internal static class AccountServices
            {
                public const char Blob = 'b';
                public const char Queue = 'q';
                public const char File = 'f';
                public const char Table = 't';
            }

            internal static class AccountResources
            {
                public const char Service = 's';
                public const char Container = 'c';
                public const char Object = 'o';
            }

            public static readonly List<char> ValidPermissionsInOrder = new List<char>
            {
                Sas.Permissions.Read,
                Sas.Permissions.Add,
                Sas.Permissions.Create,
                Sas.Permissions.Write,
                Sas.Permissions.Delete,
                Sas.Permissions.DeleteBlobVersion,
                Sas.Permissions.List,
                Sas.Permissions.Tag,
                Sas.Permissions.Update,
                Sas.Permissions.Process,
                Sas.Permissions.FilterByTags,
                Sas.Permissions.Move,
                Sas.Permissions.Execute
            };

            /// <summary>
            /// List of ports used for path style addressing.
            /// Copied from Microsoft.Azure.Storage.Core.Util
            /// </summary>
            internal static readonly int[] PathStylePorts = { 10000, 10001, 10002, 10003, 10004, 10100, 10101, 10102, 10103, 10104, 11000, 11001, 11002, 11003, 11004, 11100, 11101, 11102, 11103, 11104 };
        }

        internal static class ClientSideEncryption
        {
            public const ClientSideEncryptionVersion CurrentVersion = ClientSideEncryptionVersion.V1_0;

            public const string AgentMetadataKey = "EncryptionLibrary";

            public const string AesCbcPkcs5Padding = "AES/CBC/PKCS5Padding";

            public const string AesCbcNoPadding = "AES/CBC/NoPadding";

            public const string Aes = "AES";

            public const string EncryptionDataKey = "encryptiondata";

            public const string EncryptionMode = "FullBlob";

            public const int EncryptionBlockSize = 16;

            public const int EncryptionKeySizeBits = 256;

            public const string XMsRange = "x-ms-range";
        }

        /// <summary>
        /// XML Element Name constant values.
        /// </summary>
        internal static class Xml
        {
            internal const string Code = "Code";
            internal const string Message = "Message";
        }

        internal static class GeoRedundantRead
        {
            internal const string AlternateHostKey = "AlternateHostKey";
            internal const string ResourceNotReplicated = "ResourceNotReplicated";
        }

        internal static class HttpStatusCode
        {
            internal const int NotFound = 404;
        }
    }
    internal static class StorageExtensions
    {
        public static string EscapePath(this string path)
        {
            if (path == null)
            {
                return null;
            }

            path = path.Trim('/');
            string[] split = path.Split('/');

            for (int i = 0; i < split.Length; i++)
            {
                split[i] = Uri.EscapeDataString(split[i]);
            }

            return string.Join("/", split);
        }

        public static string UnescapePath(this string path)
        {
            if (path == null)
            {
                return null;
            }

            path = path.Trim('/');
            string[] split = path.Split('/');

            for (int i = 0; i < split.Length; i++)
            {
                split[i] = Uri.UnescapeDataString(split[i]);
            }

            return string.Join("/", split);
        }

        public static string GenerateBlockId(long offset)
        {
            // TODO #8162 - Add in a random GUID so multiple simultaneous
            // uploads won't stomp on each other and the first to commit wins.
            // This will require some changes to our test framework's
            // RecordedClientRequestIdPolicy.
            byte[] id = new byte[48]; // 48 raw bytes => 64 byte string once Base64 encoded
            BitConverter.GetBytes(offset).CopyTo(id, 0);
            return Convert.ToBase64String(id);
        }
    }

    internal sealed class UriQueryParamsCollection : Dictionary<string, string>
    {
        public UriQueryParamsCollection() : base(StringComparer.OrdinalIgnoreCase)
        {
        }

        /// <summary>
        /// Takes encoded query params string, output decoded params map
        /// </summary>
        /// <param name="encodedQueryParamString"></param>
        public UriQueryParamsCollection(string encodedQueryParamString)
        {
            if (encodedQueryParamString.StartsWith("?", true, CultureInfo.InvariantCulture))
            {
                encodedQueryParamString = encodedQueryParamString.Substring(1);
            }

            var keysAndValues = encodedQueryParamString.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var qp in keysAndValues)
            {
                var keyAndValue = qp.Split(new[] { '=' }, 2);
                if (keyAndValue.Length == 1)
                {
                    Add(WebUtility.UrlDecode(keyAndValue[0]), default); // The map's keys/values are url-decoded
                }
                else
                {
                    Add(WebUtility.UrlDecode(keyAndValue[0]),
                        WebUtility.UrlDecode(keyAndValue[1])); // The map's keys/values are url-decoded
                }
            }
        }

        // Returns the url-encoded query parameter string
        public override string ToString()
        {
            var sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kv in this)
            {
                if (sb.Length > 0)
                {
                    sb.Append('&');
                }

                sb.Append(WebUtility.UrlEncode(kv.Key)).Append('=')
                    .Append(WebUtility.UrlEncode(kv.Value)); // Query param strings are url-encoded
            }

            return sb.ToString();
        }
    }
    /// <summary>
    /// A <see cref="BlobSasQueryParameters"/> object represents the components
    /// that make up an Azure Storage Shared Access Signature's query
    /// parameters.  You can construct a new instance using
    /// <see cref="BlobSasBuilder"/>.
    ///
    /// For more information,
    /// <see href="https://docs.microsoft.com/rest/api/storageservices/create-service-sas">
    /// Create a service SAS</see>.
    /// </summary>
    public sealed class BlobSasQueryParameters : SasQueryParameters
    {
        internal UserDelegationKeyProperties KeyProperties { get; set; }

        /// <summary>
        /// Gets the Azure Active Directory object ID in GUID format.
        /// </summary>
        public string KeyObjectId => KeyProperties?.ObjectId;

        /// <summary>
        /// Gets the Azure Active Directory tenant ID in GUID format
        /// </summary>
        public string KeyTenantId => KeyProperties?.TenantId;

        /// <summary>
        /// Gets the time at which the key becomes valid.
        /// </summary>
        public DateTimeOffset KeyStartsOn => KeyProperties == null ? default : KeyProperties.StartsOn;

        /// <summary>
        /// Gets the time at which the key becomes expires.
        /// </summary>
        public DateTimeOffset KeyExpiresOn => KeyProperties == null ? default : KeyProperties.ExpiresOn;

        /// <summary>
        /// Gets the Storage service that accepts the key.
        /// </summary>
        public string KeyService => KeyProperties?.Service;

        /// <summary>
        /// Gets the Storage service version that created the key.
        /// </summary>
        public string KeyVersion => KeyProperties?.Version;

        /// <summary>
        /// Gets empty shared access signature query parameters.
        /// </summary>
        public static new BlobSasQueryParameters Empty => new BlobSasQueryParameters();

        internal BlobSasQueryParameters()
            : base()
        {
        }

        /// <summary>
        /// Creates a new BlobSasQueryParameters instance.
        /// </summary>
        internal BlobSasQueryParameters (
            string version,
            AccountSasServices? services,
            AccountSasResourceTypes? resourceTypes,
            SasProtocol protocol,
            DateTimeOffset startsOn,
            DateTimeOffset expiresOn,
            SasIPRange ipRange,
            string identifier,
            string resource,
            string permissions,
            string signature,
            string keyOid = default,
            string keyTid = default,
            DateTimeOffset keyStart = default,
            DateTimeOffset keyExpiry = default,
            string keyService = default,
            string keyVersion = default,
            string cacheControl = default,
            string contentDisposition = default,
            string contentEncoding = default,
            string contentLanguage = default,
            string contentType = default,
            string authorizedAadObjectId = default,
            string unauthorizedAadObjectId = default,
            string correlationId = default)
            : base(
                version,
                services,
                resourceTypes,
                protocol,
                startsOn,
                expiresOn,
                ipRange,
                identifier,
                resource,
                permissions,
                signature,
                cacheControl,
                contentDisposition,
                contentEncoding,
                contentLanguage,
                contentType,
                authorizedAadObjectId,
                unauthorizedAadObjectId,
                correlationId)
        {
            KeyProperties = new UserDelegationKeyProperties
            {
                ObjectId = keyOid,
                TenantId = keyTid,
                StartsOn = keyStart,
                ExpiresOn = keyExpiry,
                Service = keyService,
                Version = keyVersion
            };
        }

        /// <summary>
        /// Creates a new instance of the <see cref="BlobSasQueryParameters"/>
        /// type based on the supplied query parameters <paramref name="values"/>.
        /// All SAS-related query parameters will be removed from
        /// <paramref name="values"/>.
        /// </summary>
        /// <param name="values">URI query parameters</param>
        internal BlobSasQueryParameters (
            IDictionary<string, string> values)
            : base(values)
        {
            this.ParseKeyProperties(values);
        }

        /// <summary>
        /// Convert the SAS query parameters into a URL encoded query string.
        /// </summary>
        /// <returns>
        /// A URL encoded query string representing the SAS.
        /// </returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            KeyProperties.AppendProperties(sb);
            AppendProperties(sb);
            return sb.ToString();
        }
    }
    /// <summary>
    /// Encapsulates the shared properties used by both
    /// BlobSasQueryParameters and DataLakeSasQueryParameters.
    /// </summary>
    internal class UserDelegationKeyProperties
    {
        // skoid
        internal string ObjectId { get; set; }

        // sktid
        internal string TenantId { get; set; }

        // skt
        internal DateTimeOffset StartsOn { get; set; }

        // ske
        internal DateTimeOffset ExpiresOn { get; set; }

        // sks
        internal string Service { get; set; }

        // skv
        internal string Version { get; set; }

        /// <summary>
        /// Builds up the UserDelegationKey portion of the SAS query parameter string.
        /// </summary>
        public void AppendProperties(StringBuilder stringBuilder)
        {
            if (!string.IsNullOrWhiteSpace(ObjectId))
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyObjectId, ObjectId);
            }

            if (!string.IsNullOrWhiteSpace(TenantId))
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyTenantId, TenantId);
            }

            if (StartsOn != DateTimeOffset.MinValue)
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyStart, WebUtility.UrlEncode(StartsOn.ToString(Constants.SasTimeFormatSeconds, CultureInfo.InvariantCulture)));
            }

            if (ExpiresOn != DateTimeOffset.MinValue)
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyExpiry, WebUtility.UrlEncode(ExpiresOn.ToString(Constants.SasTimeFormatSeconds, CultureInfo.InvariantCulture)));
            }

            if (!string.IsNullOrWhiteSpace(Service))
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyService, Service);
            }

            if (!string.IsNullOrWhiteSpace(Version))
            {
                stringBuilder.AppendQueryParameter(Constants.Sas.Parameters.KeyVersion, Version);
            }
        }
    }
    internal static class SasQueryParametersExtensions
    {
        /// <summary>
        /// Parses the key properties into the QueryParameters instance.
        /// </summary>
        /// <param name="parameters">
        /// The BlobSasQueryParameters or DataLakeSasQueryParameters instance.
        /// </param>
        /// <param name="values">
        /// Dictionary of keys and values.
        /// </param>
        internal static void ParseKeyProperties(
            this
BlobSasQueryParameters parameters,
            IDictionary<string, string> values)
        {
            // make copy, otherwise we'll get an exception when we remove
            IEnumerable<KeyValuePair<string, string>> kvps = values.ToArray();
            parameters.KeyProperties = new UserDelegationKeyProperties();
            foreach (KeyValuePair<string, string> kv in kvps)
            {
                var isSasKey = true;
                // these are already decoded
                switch (kv.Key.ToUpperInvariant())
                {
                    case Constants.Sas.Parameters.KeyObjectIdUpper:
                        parameters.KeyProperties.ObjectId = kv.Value;
                        break;
                    case Constants.Sas.Parameters.KeyTenantIdUpper:
                        parameters.KeyProperties.TenantId = kv.Value;
                        break;
                    case Constants.Sas.Parameters.KeyStartUpper:
                        parameters.KeyProperties.StartsOn = DateTimeOffset.ParseExact(kv.Value, Constants.SasTimeFormatSeconds, CultureInfo.InvariantCulture);
                        break;
                    case Constants.Sas.Parameters.KeyExpiryUpper:
                        parameters.KeyProperties.ExpiresOn = DateTimeOffset.ParseExact(kv.Value, Constants.SasTimeFormatSeconds, CultureInfo.InvariantCulture);
                        break;
                    case Constants.Sas.Parameters.KeyServiceUpper:
                        parameters.KeyProperties.Service = kv.Value;
                        break;
                    case Constants.Sas.Parameters.KeyVersionUpper:
                        parameters.KeyProperties.Version = kv.Value;
                        break;

                    default:
                        isSasKey = false;
                        break;
                }

                // Remove the query parameter if it's part of the SAS
                if (isSasKey)
                {
                    values.Remove(kv.Key);
                }
            }
        }
    }
}

