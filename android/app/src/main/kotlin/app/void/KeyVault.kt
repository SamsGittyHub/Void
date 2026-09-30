package app.void

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The key-encryption key (KEK) this device's database is opened with (D-026).
 *
 * The database key is wrapped under a random 32-byte KEK, and the KEK is
 * stored only encrypted, under an AES key generated inside the Android
 * Keystore — in StrongBox where the device has one, otherwise in the TEE — that
 * never leaves it. [backing] reports where that key actually landed, not where
 * it was asked to go, so the security screen can say so (NFR-COMP-02).
 *
 * Unlike iOS, this key is not yet gated behind user presence (BiometricPrompt);
 * D-026 records the difference rather than hiding it.
 *
 * [destroy] deletes the Keystore key and the sealed KEK. That is duress
 * destruction's irreversible step (D-017): without the Keystore key the KEK,
 * and so the database, is unrecoverable. The engine's own half is
 * `VoidCore.engineDuressDestroy`, called after this.
 */
object KeyVault {
    class Opened(val kek: ByteArray, val backing: VaultBacking)

    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "void-kek-wrapper"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128

    /**
     * In `noBackupFilesDir`: app-private, and never copied by Auto Backup or
     * device-to-device transfer (FR-STOR-05).
     */
    private fun sealedFile(context: Context) = File(context.noBackupFilesDir, "kek.sealed")

    /** Release the KEK for this launch, creating it on first launch. Blocks; never on the main thread. */
    fun openOrCreate(context: Context): Opened {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val sealed = sealedFile(context)
        val existing = keyStore.getKey(ALIAS, null) as? SecretKey
        if (sealed.exists() && existing != null) {
            return Opened(unseal(existing, sealed.readBytes()), backingOf(existing))
        }
        if (sealed.exists()) {
            // The sealed KEK outlived its key: nothing can open it, or the
            // database it protects. Say so; never replace the identity.
            throw VoidException(VoidStatus.LOCKED)
        }
        // First launch, or a key left from an attempt that never finished.
        keyStore.deleteEntry(ALIAS)
        val key = generateKey()
        val kek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        val ciphertext = cipher.doFinal(kek)
        val tmp = File(sealed.parentFile, "${sealed.name}.tmp")
        tmp.writeBytes(cipher.iv + ciphertext)
        if (!tmp.renameTo(sealed)) {
            tmp.delete()
            throw VoidException(VoidStatus.FAILED)
        }
        return Opened(kek, backingOf(key))
    }

    /** Delete the Keystore key and the sealed KEK. Irreversible. */
    fun destroy(context: Context) {
        runCatching { KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS) }
        sealedFile(context).delete()
    }

    private fun generateKey(): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // NFR-COMP-02's documented fallback: the TEE, reported as such.
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    private fun unseal(key: SecretKey, sealed: ByteArray): ByteArray {
        if (sealed.size <= IV_LENGTH) throw VoidException(VoidStatus.LOCKED)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, IV_LENGTH))
        val kek = try {
            cipher.doFinal(sealed, IV_LENGTH, sealed.size - IV_LENGTH)
        } catch (e: Exception) {
            throw VoidException(VoidStatus.LOCKED)
        }
        if (kek.size != 32) throw VoidException(VoidStatus.LOCKED)
        return kek
    }

    /** Where the key actually is, as the Keystore reports it. */
    private fun backingOf(key: SecretKey): VaultBacking {
        val info = runCatching {
            SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        }.getOrNull() ?: return VaultBacking.SOFTWARE
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> VaultBacking.STRONG_BOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> VaultBacking.TEE
                else -> VaultBacking.SOFTWARE
            }
        } else {
            // API 30 cannot tell StrongBox from the TEE after the fact; claim
            // only what it can confirm.
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) VaultBacking.TEE else VaultBacking.SOFTWARE
        }
    }
}
