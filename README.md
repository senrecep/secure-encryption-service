# Encryption Service Implementation

This repository contains two implementations of an encryption service - one in TypeScript and one in C#. Both implementations provide secure data encryption and decryption capabilities using industry-standard cryptographic algorithms.

## Features

- AES-256-CBC encryption
- HMAC-SHA256 for data integrity verification
- Support for both synchronous and asynchronous operations
- Timeout and cancellation support
- Secure key and memory management
- Base64 encoding for encrypted data

## Implementations

### TypeScript Implementation (`EncryptionService.ts`)

The TypeScript implementation provides:

- Interface `IEncryptionService` defining the contract
- Class `EncryptionService` implementing the encryption/decryption logic
- Helper functions for easy one-off operations
- Built using Node.js `crypto` module

Key Features:
- Sync and async methods
- Signal-based cancellation
- Timeout support
- Automatic resource cleanup

Methods:
```typescript
encrypt(plainText: string): string
decrypt(base64CipherText: string): string
encryptAsync(plainText: string): Promise<string>
decryptAsync(base64CipherText: string): Promise<string>
encryptWithSignal(plainText: string, signal?: AbortSignal | null): Promise<string>
decryptWithSignal(base64CipherText: string, signal?: AbortSignal | null): Promise<string>
encryptWithTimeout(plainText: string, timeoutMs: number): Promise<string>
decryptWithTimeout(base64CipherText: string, timeoutMs: number): Promise<string>
```

### C# Implementation (`EncryptionService.cs`)

The C# implementation offers:

- Sealed class `EncryptionService` implementing `IDisposable`
- Object pooling for better performance
- Optimized memory usage with `Span<T>` and `ArrayPool<T>`
- Built using .NET cryptography APIs

Key Features:
- High-performance implementation
- Memory-efficient operations
- Resource pooling
- Secure memory cleanup
- CancellationToken support

Methods:
```csharp
Encrypt(string plainText): string
Decrypt(string base64CipherText): string
EncryptAsync(string plainText, CancellationToken cancellationToken = default): Task<string>
DecryptAsync(string base64CipherText, CancellationToken cancellationToken = default): Task<string>
Encrypt(string plainText, TimeSpan timeout): string
Decrypt(string base64CipherText, TimeSpan timeout): string
```

## Security Features

Both implementations include:

1. Secure key validation
2. IV (Initialization Vector) generation
3. HMAC verification
4. Secure memory cleanup
5. Input validation
6. Timing attack protection

## Usage

### TypeScript Example

```typescript
// One-off encryption/decryption
const encrypted = encrypt(plainText, base64Key);
const decrypted = decrypt(encrypted, base64Key);

// Using the service instance
const service = new EncryptionService(base64Key);
try {
    const encrypted = await service.encryptAsync(plainText);
    const decrypted = await service.decryptAsync(encrypted);
} finally {
    service.dispose();
}
```

### C# Example

```csharp
// Using the service with using statement
using var service = new EncryptionService(base64Key);

// Synchronous operations
string encrypted = service.Encrypt(plainText);
string decrypted = service.Decrypt(encrypted);

// Asynchronous operations with cancellation
using var cts = new CancellationTokenSource();
string encryptedAsync = await service.EncryptAsync(plainText, cts.Token);
string decryptedAsync = await service.DecryptAsync(encryptedAsync, cts.Token);
```

## Technical Details

### Encryption Algorithm
- AES-256 in CBC mode
- PKCS7 padding
- 256-bit key size
- 128-bit IV size
- HMAC-SHA256 for integrity verification

### Constants
- IV Size: 16 bytes
- HMAC Size: 32 bytes
- Key Size: 32 bytes (256-bit)

## Dependencies

### TypeScript Version
- Node.js
- `crypto` module
- TypeScript compiler
- `@types/node` for TypeScript definitions

### C# Version
- .NET 6.0 or later
- System.Security.Cryptography
- Microsoft.Extensions.ObjectPool

## Best Practices

1. Always dispose of the service instance after use
2. Use async methods for better performance in I/O-bound scenarios
3. Implement proper error handling
4. Secure your encryption keys
5. Use timeouts for time-sensitive operations
6. Clear sensitive data from memory when no longer needed

## Security Considerations

1. Keep encryption keys secure and never store them in code
2. Use secure random number generation for IVs
3. Implement proper key rotation policies
4. Monitor for cryptographic exceptions
5. Use secure key derivation when converting from passwords
6. Regularly update cryptographic libraries

## Performance Considerations

1. C# implementation uses object pooling for better performance
2. Both implementations support cancellation for long-running operations
3. C# version uses `Span<T>` for efficient memory operations
4. Both implement proper resource cleanup
5. Buffer sizes are optimized for common use cases 

## Code of Conduct

We are committed to fostering a welcoming and inclusive community. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) for details on our code of conduct and the process for reporting unacceptable behavior.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENCE) file for details. 