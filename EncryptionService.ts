import crypto from "crypto";

/**
 * Interface defining the contract for encryption and decryption operations.
 * Provides both synchronous and asynchronous methods with optional timeout and cancellation support.
 */
interface IEncryptionService {
  encrypt(plainText: string): string;
  encryptAsync(plainText: string): Promise<string>;
  encryptWithSignal(
    plainText: string,
    signal?: AbortSignal | null
  ): Promise<string>;
  encryptWithTimeout(plainText: string, timeoutMs: number): Promise<string>;
  decrypt(base64CipherText: string): string;
  decryptAsync(base64CipherText: string): Promise<string>;
  decryptWithSignal(
    base64CipherText: string,
    signal?: AbortSignal | null
  ): Promise<string>;
  decryptWithTimeout(
    base64CipherText: string,
    timeoutMs: number
  ): Promise<string>;
  dispose(): void;
}

/**
 * Implements secure encryption and decryption services using AES-256 in CBC mode with HMAC-SHA256.
 * Features include:
 * - AES-256 encryption in CBC mode
 * - Cryptographically secure random IV generation
 * - HMAC-SHA256 for integrity verification
 * - Secure key management with proper disposal
 * - Support for both sync and async operations
 * - Timeout and cancellation support
 */
class EncryptionService implements IEncryptionService {
  // Constants
  private static readonly IV_SIZE: number = 16;
  private static readonly HMAC_SIZE: number = 32;
  private static readonly KEY_SIZE: number = 32; // 256-bit
  private static readonly DEFAULT_TIMEOUT: number = 30000; // 30 seconds

  private readonly _encryptionKey: Buffer;
  private _isDisposed: boolean;

  constructor(base64Key: string) {
    this._validateEncryptionKey(base64Key);
    this._encryptionKey = Buffer.from(base64Key, "base64");
    this._isDisposed = false;
  }

  /**
   * Encrypts the given plain text synchronously using the default timeout.
   * @param plainText - The text to encrypt
   * @returns Base64 encoded encrypted string
   * @throws Error if the service is disposed or input is invalid
   */
  public encrypt(plainText: string): string {
    this._validateInputData(plainText);
    return this._performEncryption(plainText);
  }

  /**
   * Decrypts the given Base64 encoded cipher text synchronously.
   * @param base64CipherText - The Base64 encoded cipher text to decrypt
   * @returns Decrypted plain text
   * @throws Error if the service is disposed, input is invalid, or integrity check fails
   */
  public decrypt(base64CipherText: string): string {
    this._validateInputData(base64CipherText);
    return this._performDecryption(base64CipherText);
  }

  /**
   * Encrypts the given plain text asynchronously using the default timeout.
   * @param plainText - The text to encrypt
   * @returns Promise resolving to Base64 encoded encrypted string
   * @throws Error if the service is disposed or input is invalid
   */
  public async encryptAsync(plainText: string): Promise<string> {
    return await this.encryptWithTimeout(
      plainText,
      EncryptionService.DEFAULT_TIMEOUT
    );
  }

  /**
   * Encrypts the given plain text with cancellation support.
   * @param plainText - The text to encrypt
   * @param signal - Optional AbortSignal for cancellation
   * @returns Promise resolving to Base64 encoded encrypted string
   * @throws Error if the operation is cancelled, service is disposed, or input is invalid
   */
  public encryptWithSignal(
    plainText: string,
    signal: AbortSignal | null = null
  ): Promise<string> {
    this._validateInputData(plainText);
    return this._performEncryptionAsync(plainText, signal);
  }

  /**
   * Encrypts the given plain text with a specified timeout.
   * @param plainText - The text to encrypt
   * @param timeoutMs - Maximum time in milliseconds allowed for the operation
   * @returns Promise resolving to Base64 encoded encrypted string
   * @throws Error if the operation times out, service is disposed, or input is invalid
   */
  public async encryptWithTimeout(
    plainText: string,
    timeoutMs: number
  ): Promise<string> {
    this._validateInputData(plainText);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await this._performEncryptionAsync(plainText, controller.signal);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Decrypts the given Base64 encoded cipher text asynchronously.
   * @param base64CipherText - The Base64 encoded cipher text to decrypt
   * @returns Promise resolving to decrypted plain text
   * @throws Error if the service is disposed, input is invalid, or integrity check fails
   */
  public async decryptAsync(base64CipherText: string): Promise<string> {
    return await this.decryptWithTimeout(
      base64CipherText,
      EncryptionService.DEFAULT_TIMEOUT
    );
  }

  /**
   * Decrypts the given Base64 encoded cipher text with cancellation support.
   * @param base64CipherText - The Base64 encoded cipher text to decrypt
   * @param signal - Optional AbortSignal for cancellation
   * @returns Promise resolving to decrypted plain text
   * @throws Error if cancelled, service is disposed, input is invalid, or integrity check fails
   */
  public decryptWithSignal(
    base64CipherText: string,
    signal: AbortSignal | null = null
  ): Promise<string> {
    this._validateInputData(base64CipherText);
    return this._performDecryptionAsync(base64CipherText, signal);
  }

  /**
   * Decrypts the given Base64 encoded cipher text with a specified timeout.
   * @param base64CipherText - The Base64 encoded cipher text to decrypt
   * @param timeoutMs - Maximum time in milliseconds allowed for the operation
   * @returns Promise resolving to decrypted plain text
   * @throws Error if times out, service is disposed, input is invalid, or integrity check fails
   */
  public async decryptWithTimeout(
    base64CipherText: string,
    timeoutMs: number
  ): Promise<string> {
    this._validateInputData(base64CipherText);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await this._performDecryptionAsync(
        base64CipherText,
        controller.signal
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Disposes the encryption service by securely clearing the encryption key from memory.
   */
  public dispose(): void {
    if (!this._isDisposed) {
      this._isDisposed = true;
      if (this._encryptionKey) {
        this._encryptionKey.fill(0); // Clear the key from memory
      }
    }
  }

  // Private Methods
  private _performEncryption(plainText: string): string {
    // Generate IV
    const iv = crypto.randomBytes(EncryptionService.IV_SIZE);

    // Convert text to bytes with UTF-8 encoding
    const plainBytes = Buffer.from(plainText, "utf8");

    // Encrypt the data
    const encryptedData = this._encryptDataWithIV(plainBytes, iv, null);

    // Combine IV and encrypted data
    const combined = Buffer.concat([iv, encryptedData]);

    // Calculate HMAC
    const hmac = this._calculateHMAC(combined);

    // Combine HMAC + IV + encrypted data
    const result = Buffer.concat([hmac, combined]);

    // Return as base64
    return result.toString("base64");
  }

  private async _performEncryptionAsync(
    plainText: string,
    signal: AbortSignal | null
  ): Promise<string> {
    // Generate IV
    const iv = crypto.randomBytes(EncryptionService.IV_SIZE);

    // Convert text to bytes with UTF-8 encoding
    const plainBytes = Buffer.from(plainText, "utf8");

    // Encrypt the data
    const encryptedData = this._encryptDataWithIV(plainBytes, iv, signal);

    // Combine IV and encrypted data
    const combined = Buffer.concat([iv, encryptedData]);

    // Calculate HMAC
    const hmac = this._calculateHMAC(combined);

    // Combine HMAC + IV + encrypted data
    const result = Buffer.concat([hmac, combined]);

    // Return as base64
    return result.toString("base64");
  }

  private _performDecryption(base64CipherText: string): string {
    const cipherData = this._parseAndValidateBase64Data(base64CipherText);

    const hmac = cipherData.slice(0, EncryptionService.HMAC_SIZE);
    const encryptedData = cipherData.slice(EncryptionService.HMAC_SIZE);

    this._verifyHMAC(encryptedData, hmac);

    const iv = encryptedData.slice(0, EncryptionService.IV_SIZE);
    const cipherText = encryptedData.slice(EncryptionService.IV_SIZE);

    const result = this._decryptDataWithIV(cipherText, iv);
    cipherData.fill(0); // Clear sensitive data
    return result;
  }

  private async _performDecryptionAsync(
    base64CipherText: string,
    signal: AbortSignal | null
  ): Promise<string> {
    const cipherData = this._parseAndValidateBase64Data(base64CipherText);

    const hmac = cipherData.slice(0, EncryptionService.HMAC_SIZE);
    const encryptedData = cipherData.slice(EncryptionService.HMAC_SIZE);

    this._verifyHMAC(encryptedData, hmac);

    const iv = encryptedData.slice(0, EncryptionService.IV_SIZE);
    const cipherText = encryptedData.slice(EncryptionService.IV_SIZE);

    const result = await this._decryptDataWithIVAsync(cipherText, iv, signal);
    cipherData.fill(0); // Clear sensitive data
    return result;
  }

  private _encryptDataWithIV(
    plainBytes: Buffer,
    iv: Buffer,
    signal: AbortSignal | null
  ): Buffer {
    if (signal?.aborted) {
      throw new Error("Operation cancelled");
    }

    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      this._encryptionKey,
      iv
    );
    return Buffer.concat([cipher.update(plainBytes), cipher.final()]);
  }

  private async _decryptDataWithIVAsync(
    cipherText: Buffer,
    iv: Buffer,
    signal: AbortSignal | null
  ): Promise<string> {
    if (signal?.aborted) {
      throw new Error("Operation cancelled");
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      this._encryptionKey,
      iv
    );
    const decrypted = Buffer.concat([
      decipher.update(cipherText),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  }

  private _decryptDataWithIV(cipherText: Buffer, iv: Buffer): string {
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      this._encryptionKey,
      iv
    );
    const decrypted = Buffer.concat([
      decipher.update(cipherText),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  }

  private _calculateHMAC(data: Buffer): Buffer {
    const hmac = crypto.createHmac("sha256", this._encryptionKey);
    hmac.update(data);
    return hmac.digest();
  }

  private _verifyHMAC(data: Buffer, expectedHmac: Buffer): void {
    const actualHmac = this._calculateHMAC(data);
    if (!crypto.timingSafeEqual(actualHmac, expectedHmac)) {
      throw new Error(
        "Data verification failed! Data integrity might be compromised."
      );
    }
  }

  private _parseAndValidateBase64Data(base64Text: string): Buffer {
    let data: Buffer;
    try {
      data = Buffer.from(base64Text, "base64");
    } catch {
      throw new Error("Invalid Base64 format for encrypted text!");
    }

    if (data.length < EncryptionService.HMAC_SIZE + EncryptionService.IV_SIZE) {
      data.fill(0);
      throw new Error("Invalid encrypted text length!");
    }

    return data;
  }

  private _validateEncryptionKey(base64Key: string): void {
    if (!base64Key) {
      throw new Error("Encryption key cannot be empty!");
    }

    let key: Buffer;
    try {
      key = Buffer.from(base64Key, "base64");
    } catch {
      throw new Error("Invalid Base64 format for encryption key!");
    }

    const isValidLength = key.length === EncryptionService.KEY_SIZE;
    key.fill(0);

    if (!isValidLength) {
      throw new Error(
        `Key length must be ${EncryptionService.KEY_SIZE} bytes!`
      );
    }
  }

  private _validateInputData(input: string): void {
    if (this._isDisposed) {
      throw new Error("Cannot access a disposed EncryptionService.");
    }
    if (!input) {
      throw new Error("Input data cannot be empty!");
    }
  }
}

// Helper functions
/**
 * Helper function to encrypt text synchronously with automatic resource cleanup.
 * @param plainText - The text to encrypt
 * @param base64Key - The Base64 encoded encryption key
 * @returns Base64 encoded encrypted string
 */
function encrypt(plainText: string, base64Key: string): string {
  const encryptor = new EncryptionService(base64Key);
  try {
    return encryptor.encrypt(plainText);
  } finally {
    encryptor.dispose();
  }
}

/**
 * Helper function to decrypt text synchronously with automatic resource cleanup.
 * @param encryptedValue - The Base64 encoded encrypted text
 * @param base64Key - The Base64 encoded encryption key
 * @returns Decrypted plain text
 */
function decrypt(encryptedValue: string, base64Key: string): string {
  const decryptor = new EncryptionService(base64Key);
  try {
    return decryptor.decrypt(encryptedValue);
  } finally {
    decryptor.dispose();
  }
}

/**
 * Helper function to encrypt text asynchronously with automatic resource cleanup.
 * @param plainText - The text to encrypt
 * @param base64Key - The Base64 encoded encryption key
 * @returns Promise resolving to Base64 encoded encrypted string
 */
async function encryptAsync(
  plainText: string,
  base64Key: string
): Promise<string> {
  const encryptor = new EncryptionService(base64Key);
  try {
    return await encryptor.encryptAsync(plainText);
  } finally {
    encryptor.dispose();
  }
}

/**
 * Helper function to decrypt text asynchronously with automatic resource cleanup.
 * @param encryptedValue - The Base64 encoded encrypted text
 * @param base64Key - The Base64 encoded encryption key
 * @returns Promise resolving to decrypted plain text
 */
async function decryptAsync(
  encryptedValue: string,
  base64Key: string
): Promise<string> {
  const decryptor = new EncryptionService(base64Key);
  try {
    return await decryptor.decryptAsync(encryptedValue);
  } finally {
    decryptor.dispose();
  }
}

/**
 * Helper function to encrypt text with cancellation support and automatic resource cleanup.
 * @param plainText - The text to encrypt
 * @param base64Key - The Base64 encoded encryption key
 * @param signal - Optional AbortSignal for cancellation
 * @returns Promise resolving to Base64 encoded encrypted string
 */
async function encryptWithSignal(
  plainText: string,
  base64Key: string,
  signal: AbortSignal | null = null
): Promise<string> {
  const encryptor = new EncryptionService(base64Key);
  try {
    return await encryptor.encryptWithSignal(plainText, signal);
  } finally {
    encryptor.dispose();
  }
}

/**
 * Helper function to decrypt text with cancellation support and automatic resource cleanup.
 * @param encryptedValue - The Base64 encoded encrypted text
 * @param base64Key - The Base64 encoded encryption key
 * @param signal - Optional AbortSignal for cancellation
 * @returns Promise resolving to decrypted plain text
 */
async function decryptWithSignal(
  encryptedValue: string,
  base64Key: string,
  signal: AbortSignal | null = null
): Promise<string> {
  const decryptor = new EncryptionService(base64Key);
  try {
    return await decryptor.decryptWithSignal(encryptedValue, signal);
  } finally {
    decryptor.dispose();
  }
}

export {
  IEncryptionService,
  EncryptionService,
  encrypt,
  decrypt,
  encryptAsync,
  decryptAsync,
  encryptWithSignal,
  decryptWithSignal,
};

