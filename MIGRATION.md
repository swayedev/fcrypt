# fcrypt Migration Guide

This guide covers migration from pre-0.3 encrypted formats to the v1 release-candidate APIs.

## Format Changes

Starting in v0.3, fcrypt writes a versioned AES-GCM record format for file and stream encryption.

New file and stream records begin with:

```text
FCRYPT || version || algorithm || nonceSize || lenSize
```

After the header, data is stored as repeated records:

```text
nonce || uint32(ciphertextLen) || ciphertext
```

## Supported Legacy Reads

Current decrypt paths can read:

- Pre-0.3 headerless AES-GCM file records.
- Pre-0.3 AES-CTR streams.

Current encrypt paths always write the new authenticated versioned format.

## Migrating Files

To migrate older headerless file records, decrypt and re-encrypt with the current APIs:

```go
if err := fcrypt.ReEncryptFileToFile(
    "legacy.fcrypt",
    "current.fcrypt",
    oldKey,
    newKey,
    fcrypt.DefaultChunkSize,
); err != nil {
    return err
}
```

If the key is unchanged but the format needs upgrading, pass the same key as `oldKey` and `newKey`.

## Migrating Streams

`StreamDecrypt` can read legacy AES-CTR streams. Re-encrypt the plaintext immediately with `StreamEncrypt`:

```go
legacyPlaintext, err := fcrypt.StreamDecrypt(legacyCiphertext, key)
if err != nil {
    return err
}

currentCiphertext, err := fcrypt.StreamEncrypt(legacyPlaintext, key)
if err != nil {
    return err
}
```

Legacy AES-CTR streams are unauthenticated. If the ciphertext may have been modified, there is no cryptographic integrity signal in the legacy format.

## Legacy Helpers

The following helpers exist only for migration tests and controlled interoperability workflows:

- `LegacyEncryptFileToFile`
- `LegacyStreamEncrypt`
- `LegacyStreamDecrypt`

New applications should not use these helpers for new data.

## Key Rotation

For new code, prefer the `KeyStore` API:

```go
store, err := fcrypt.NewMemoryKeyStore()
if err != nil {
    return err
}

key, err := store.Rotate(ctx, fcrypt.RotationPolicy{
    Passphrase: "your-secure-passphrase",
})
if err != nil {
    return err
}
```

External backends should use adapter packages such as `adapters/openbao`, `adapters/vault`, or cloud KMS adapters.
