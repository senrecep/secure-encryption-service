using System.Security.Cryptography;
using System.Text;
using System.Buffers;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.ObjectPool;

public interface IEncryptionService : IDisposable
{
    /// <summary>
    /// Encrypts the plain text using default timeout.
    /// </summary>
    /// <param name="plainText">The text to encrypt</param>
    /// <returns>Base64 encoded encrypted string</returns>
    string Encrypt(string plainText);

    /// <summary>
    /// Encrypts the plain text asynchronously.
    /// </summary>
    /// <param name="plainText">The text to encrypt</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
    /// <returns>Base64 encoded encrypted string</returns>
    Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default);

    /// <summary>
    /// Encrypts the plain text with a specified timeout.
    /// </summary>
    /// <param name="plainText">The text to encrypt</param>
    /// <param name="timeout">Maximum time allowed for the operation</param>
    /// <returns>Base64 encoded encrypted string</returns>
    string Encrypt(string plainText, TimeSpan timeout);

    /// <summary>
    /// Decrypts the cipher text using default timeout.
    /// </summary>
    /// <param name="base64CipherText">The Base64 encoded cipher text to decrypt</param>
    /// <returns>Decrypted plain text</returns>
    string Decrypt(string base64CipherText);

    /// <summary>
    /// Decrypts the cipher text asynchronously.
    /// </summary>
    /// <param name="base64CipherText">The Base64 encoded cipher text to decrypt</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
    /// <returns>Decrypted plain text</returns>
    Task<string> DecryptAsync(string base64CipherText, CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts the cipher text with a specified timeout.
    /// </summary>
    /// <param name="base64CipherText">The Base64 encoded cipher text to decrypt</param>
    /// <param name="timeout">Maximum time allowed for the operation</param>
    /// <returns>Decrypted plain text</returns>
    string Decrypt(string base64CipherText, TimeSpan timeout);
}

/// <summary>
/// Provides secure encryption and decryption services using AES-256 in CBC mode with HMAC-SHA256 for integrity verification.
/// This service implements object pooling for better performance and proper resource management.
/// </summary>
/// <remarks>
/// The service uses the following security features:
/// - AES-256 encryption in CBC mode with PKCS7 padding
/// - Cryptographically secure random IV generation
/// - HMAC-SHA256 for integrity verification
/// - Secure key management with proper disposal
/// - Object pooling for better performance
/// </remarks>
public sealed class EncryptionService : IEncryptionService
{
    #region Constants
    private const int IvSize = 16;
    private const int HmacSize = 32;
    private const int KeySize = 32; // 256-bit
    private const int MinBufferSize = 1024; // 1KB
    private const int MaxBufferSize = 1024 * 1024; // 1MB
    private const int DefaultBufferSize = 4096; // 4KB
    private const int PoolSize = 32; // Maximum number of pooled objects
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    #endregion

    #region Pool Policies
    private sealed class AesPoolPolicy : PooledObjectPolicy<Aes>
    {
        public override Aes Create()
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 256;
            return aes;
        }

        public override bool Return(Aes obj)
        {
            if (obj?.Key == null)
                return false;

            Array.Clear(obj.Key, 0, obj.Key.Length);
            return true;
        }
    }

    private sealed class HmacPoolPolicy : PooledObjectPolicy<HMACSHA256>
    {
        private readonly byte[] _key;

        public HmacPoolPolicy(byte[] key) => _key = key;

        public override HMACSHA256 Create() => new HMACSHA256(_key);

        public override bool Return(HMACSHA256 obj)
        {
            if (obj?.Key == null)
                return false;

            Array.Clear(obj.Key, 0, obj.Key.Length);
            return true;
        }
    }
    #endregion

    #region Fields
    private readonly byte[] _key;
    private readonly DefaultObjectPool<Aes> _aesPool;
    private readonly DefaultObjectPool<HMACSHA256> _hmacPool;
    private bool _disposed;
    #endregion

    #region Constructor & Dispose
    /// <summary>
    /// Initializes a new instance of the EncryptionService with the specified encryption key.
    /// </summary>
    /// <param name="base64Key">The Base64 encoded 256-bit encryption key</param>
    /// <exception cref="ArgumentException">Thrown when the key is invalid or has incorrect length</exception>
    public EncryptionService(string base64Key)
    {
        ValidateKey(base64Key);
        _key = Convert.FromBase64String(base64Key);
        _aesPool = new DefaultObjectPool<Aes>(new AesPoolPolicy(), PoolSize);
        _hmacPool = new DefaultObjectPool<HMACSHA256>(new HmacPoolPolicy(_key), PoolSize);
    }

    /// <summary>
    /// Disposes the encryption service and securely clears the encryption key from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            Array.Clear(_key, 0, _key.Length);
            GC.SuppressFinalize(this);
        }
    }
    #endregion

    #region Public Methods
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Encrypt(string plainText) => Encrypt(plainText, DefaultTimeout);

    public Task<string> EncryptAsync(string plainText, CancellationToken cancellationToken = default)
    {
        ValidateInput(plainText);
        return Task.FromResult(EncryptInternal(plainText.AsSpan(), cancellationToken));
    }

    public string Encrypt(string plainText, TimeSpan timeout)
    {
        ValidateInput(plainText);
        using var cts = new CancellationTokenSource(timeout);
        return EncryptInternal(plainText.AsSpan(), cts.Token);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Decrypt(string base64CipherText) => Decrypt(base64CipherText, DefaultTimeout);

    public Task<string> DecryptAsync(string base64CipherText, CancellationToken cancellationToken = default)
    {
        ValidateInput(base64CipherText);
        return Task.FromResult(DecryptInternal(base64CipherText, cancellationToken));
    }

    public string Decrypt(string base64CipherText, TimeSpan timeout)
    {
        ValidateInput(base64CipherText);
        using var cts = new CancellationTokenSource(timeout);
        return DecryptInternal(base64CipherText, cts.Token);
    }
    #endregion

    #region Private Methods
    private string EncryptInternal(ReadOnlySpan<char> plainText, CancellationToken cancellationToken)
    {
        // Get IV
        Span<byte> iv = stackalloc byte[IvSize];
        RandomNumberGenerator.Fill(iv);

        // Get plain bytes with minimal allocations
        int maxPlainTextBytes = Encoding.UTF8.GetMaxByteCount(plainText.Length);
        byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(maxPlainTextBytes);
        int actualPlainTextBytes = 0;

        actualPlainTextBytes = Encoding.UTF8.GetBytes(plainText, rentedBuffer);
        byte[] encryptedData = EncryptData(rentedBuffer.AsSpan(0, actualPlainTextBytes), iv, cancellationToken);
        Array.Clear(rentedBuffer, 0, actualPlainTextBytes);
        ArrayPool<byte>.Shared.Return(rentedBuffer);

        // Combine IV and encrypted data on stack
        Span<byte> combined = stackalloc byte[iv.Length + encryptedData.Length];
        iv.CopyTo(combined);
        encryptedData.CopyTo(combined[iv.Length..]);

        // Calculate HMAC
        byte[] hmac = ComputeHmac(combined);

        // Prepare final result with minimal allocations
        byte[] result = new byte[HmacSize + combined.Length];
        hmac.CopyTo(result.AsSpan(0, HmacSize));
        combined.CopyTo(result.AsSpan(HmacSize));

        return Convert.ToBase64String(result);
    }

    private string DecryptInternal(string base64CipherText, CancellationToken cancellationToken)
    {
        byte[] cipherData = ParseAndValidateBase64(base64CipherText);
        ReadOnlySpan<byte> hmac = cipherData.AsSpan(0, HmacSize);
        ReadOnlySpan<byte> encryptedData = cipherData.AsSpan(HmacSize);

        ValidateHmac(encryptedData, hmac);

        ReadOnlySpan<byte> iv = encryptedData[..IvSize];
        ReadOnlySpan<byte> cipherText = encryptedData[IvSize..];

        string result = DecryptData(cipherText, iv, cancellationToken);
        Array.Clear(cipherData, 0, cipherData.Length);
        return result;
    }

    /// <summary>
    /// Encrypts the given plain text data with the specified initialization vector.
    /// </summary>
    /// <param name="plainBytes">The plain text data to encrypt</param>
    /// <param name="iv">The initialization vector for encryption</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests</param>
    /// <returns>The encrypted data</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private byte[] EncryptData(ReadOnlySpan<byte> plainBytes, ReadOnlySpan<byte> iv, CancellationToken cancellationToken)
    {
        var aes = _aesPool.Get();
        if (aes is null) return Array.Empty<byte>();

        aes.Key = _key;
        aes.IV = iv.ToArray();

        using var encryptor = aes.CreateEncryptor();
        int maxEncryptedSize = plainBytes.Length + (aes.BlockSize / 8);
        int bufferSize = Math.Min(Math.Max(maxEncryptedSize, MinBufferSize), MaxBufferSize);

        using var ms = new MemoryStream(bufferSize);
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write, leaveOpen: true))
        {
            cs.Write(plainBytes);
            cs.FlushFinalBlock();
        }

        cancellationToken.ThrowIfCancellationRequested();
        _aesPool.Return(aes);
        return ms.ToArray();
    }

    /// <summary>
    /// Decrypts the given cipher text using the specified initialization vector.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt</param>
    /// <param name="iv">The initialization vector used for encryption</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests</param>
    /// <returns>The decrypted data as a string</returns>
    private string DecryptData(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> iv, CancellationToken cancellationToken)
    {
        var aes = _aesPool.Get();
        if (aes is null) return string.Empty;

        aes.Key = _key;
        aes.IV = iv.ToArray();

        using var decryptor = aes.CreateDecryptor();
        int bufferSize = Math.Min(Math.Max(cipherText.Length, MinBufferSize), MaxBufferSize);
        using var outputBuffer = new MemoryStream(bufferSize);

        var rentedBuffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        using (var ms = new MemoryStream(cipherText.ToArray(), writable: false))
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        {
            int bytesRead;
            while ((bytesRead = cs.Read(rentedBuffer, 0, bufferSize)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                outputBuffer.Write(rentedBuffer, 0, bytesRead);
            }
        }

        Array.Clear(rentedBuffer, 0, rentedBuffer.Length);
        ArrayPool<byte>.Shared.Return(rentedBuffer);
        _aesPool.Return(aes);

        outputBuffer.Position = 0;
        using var reader = new StreamReader(outputBuffer, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// Computes the HMAC-SHA256 for the given data using the encryption key.
    /// </summary>
    /// <param name="data">The data to compute HMAC for</param>
    /// <returns>The computed HMAC</returns>
    private byte[] ComputeHmac(ReadOnlySpan<byte> data)
    {
        var hmac = _hmacPool.Get();
        if (hmac is null) return Array.Empty<byte>();

        var result = hmac.ComputeHash(data.ToArray());
        _hmacPool.Return(hmac);
        return result;
    }

    /// <summary>
    /// Validates the HMAC of the encrypted data to ensure data integrity.
    /// </summary>
    /// <param name="data">The encrypted data to validate</param>
    /// <param name="expectedHmac">The expected HMAC value</param>
    /// <exception cref="CryptographicException">Thrown when HMAC validation fails</exception>
    private void ValidateHmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> expectedHmac)
    {
        var hmac = _hmacPool.Get();
        if (hmac is null) return;

        var actualHmac = hmac.ComputeHash(data.ToArray());
        var isValid = CryptographicOperations.FixedTimeEquals(actualHmac, expectedHmac.ToArray());

        Array.Clear(actualHmac, 0, actualHmac.Length);
        _hmacPool.Return(hmac);

        if (!isValid)
        {
            throw new CryptographicException("Data verification failed! Data integrity might be compromised.");
        }
    }

    /// <summary>
    /// Parses and validates the Base64 encoded cipher text.
    /// </summary>
    /// <param name="base64Text">The Base64 encoded cipher text to parse</param>
    /// <returns>The decoded cipher data</returns>
    /// <exception cref="ArgumentException">Thrown when the input is not valid Base64</exception>
    /// <exception cref="CryptographicException">Thrown when the decoded data length is invalid</exception>
    private static byte[] ParseAndValidateBase64(string base64Text)
    {
        if (!Convert.TryFromBase64String(base64Text, new byte[base64Text.Length], out _))
        {
            throw new ArgumentException("Invalid Base64 format for encrypted text!");
        }

        var data = Convert.FromBase64String(base64Text);
        if (data.Length < HmacSize + IvSize)
        {
            Array.Clear(data, 0, data.Length);
            throw new CryptographicException("Invalid encrypted text length!");
        }

        return data;
    }

    /// <summary>
    /// Validates the encryption key format and length.
    /// </summary>
    /// <param name="base64Key">The Base64 encoded key to validate</param>
    /// <exception cref="ArgumentException">Thrown when the key is invalid or has incorrect length</exception>
    private static void ValidateKey(string base64Key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Key, nameof(base64Key));

        if (!Convert.TryFromBase64String(base64Key, new byte[base64Key.Length], out _))
        {
            throw new ArgumentException("Invalid Base64 format for encryption key!", nameof(base64Key));
        }

        var key = Convert.FromBase64String(base64Key);
        var isValidLength = key.Length == KeySize;
        Array.Clear(key, 0, key.Length);

        if (!isValidLength)
        {
            throw new ArgumentException($"Key length must be {KeySize} bytes!", nameof(base64Key));
        }
    }

    /// <summary>
    /// Validates the input data and service state.
    /// </summary>
    /// <param name="input">The input data to validate</param>
    /// <exception cref="ObjectDisposedException">Thrown when the service is disposed</exception>
    /// <exception cref="ArgumentException">Thrown when the input is null or empty</exception>
    private void ValidateInput(string input)
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(EncryptionService));
        ArgumentException.ThrowIfNullOrWhiteSpace(input, nameof(input));
    }
    #endregion
}
