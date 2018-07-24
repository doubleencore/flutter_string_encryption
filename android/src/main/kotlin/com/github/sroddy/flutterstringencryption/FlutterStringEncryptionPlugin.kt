package com.github.sroddy.flutterstringencryption

import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.PluginRegistry.Registrar

import com.tozny.crypto.android.AesCbcWithIntegrity.*
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec.F4
import android.util.Base64
import android.util.Log
import java.security.*
import javax.crypto.Cipher
import java.security.spec.X509EncodedKeySpec


class FlutterStringEncryptionPlugin(): MethodCallHandler {
  private val _androidKeyStore = "AndroidKeyStore"
  companion object {
    @JvmStatic
    fun registerWith(registrar: Registrar): Unit {
      val channel = MethodChannel(registrar.messenger(), "flutter_string_encryption")
      channel.setMethodCallHandler(FlutterStringEncryptionPlugin())
    }
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    when (call.method) {
      "decrypt" -> {
        val data = call.argument<String>("data")
        val keyString = call.argument<String>("key")

        val civ = CipherTextIvMac(data)
        try {
          val decrypted = decryptString(civ, keys(keyString))
          result.success(decrypted)
        } catch (e: GeneralSecurityException) {
          print(e)
          result.error("mac_mismatch", "Mac don't match", null)
        }
      }
      "encrypt" -> {
        val string = call.argument<String>("string")
        val keyString = call.argument<String>("key")

        val encrypted = encrypt(string, keys(keyString))

        result.success(encrypted.toString())
      }
      "generate_random_key" -> {
        val key = generateKey()
        val keyString = keyString(key)

        result.success(keyString)
      }
      "generate_salt" -> {
        val salt = generateSalt()
        val base64Salt = saltString(salt)

        result.success(base64Salt)
      }
      "generate_key_from_password" -> {
        val password = call.argument<String>("password")
        val salt = call.argument<String>("salt")

        val key = generateKeyFromPassword(password, salt)
        val keyString = keyString(key)

        result.success(keyString)
      }
      "generate_public_private_key_pair" -> {
        val tag = call.argument<String>("tag")
        val keyPair = generateKeyPair(tag)
        val b64publicKey = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
        result.success(b64publicKey)
      }
      "get_public_key" -> {
        val tag = call.argument<String>("tag")
        try {
          val publicKey = getPublicKey(tag)
          publicKey?.let {
            result.success(Base64.encodeToString(it.encoded, Base64.DEFAULT))
          }
        } catch (e: Exception) {
          result.error("public_key_error", "Error getting public key.", null)
        }
      }
      "get_private_key" -> {
        val tag = call.argument<String>("tag")
        try {
          val privateKey = getPrivateKey(tag)
          privateKey?.let {
            result.success(Base64.encodeToString(it.encoded, Base64.DEFAULT))
          }
        } catch (e: Exception) {
          result.error("private_key_error", "Error getting private key.", null)
        }
      }
      "delete_public_private_key_pair" -> {
        val tag = call.argument<String>("tag")
        try {
            deleteKey(tag)
        } catch (e: Exception) {
          result.error("delete_key_error", "Error deleting key.", null)
        }
      }
      "encrypt_message_with_public_key" -> {
        val message = call.argument<String>("message")
        val publicKey = call.argument<String>("public_key")
        val encryptedMessage = encryptMessageWithKey(message, publicKey)
        try {
          result.success(encryptedMessage)
        } catch (e: Exception) {
          result.error("encryption_error", "Error encrypting message.", null)
        }

      }
      "decrypt_message_with_key" -> {
        val message = call.argument<String>("message")
        val tag = call.argument<String>("tag")
        try {
          result.success(decryptMessageWithKey(message, tag))
        } catch (e: Exception) {
          result.error("decryption_error", "Error decrypting message.", null)
        }
      }
      else -> result.notImplemented()
    }
  }

  private fun decryptMessageWithKey(message: String, tag: String): String {
    val privateKey = getPrivateKey(tag)
    val decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey)
    var clearText = decryptCipher.doFinal(Base64.decode(message, Base64.DEFAULT))
    return clearText.toString(charset("UTF-8"))

  }

  private fun encryptMessageWithKey(message: String, base64key: String): String {
    val publicBytes = Base64.decode(base64key, Base64.DEFAULT)
    val keySpec = X509EncodedKeySpec(publicBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKey = keyFactory.generatePublic(keySpec)
    val encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val cryptedBytes = encryptCipher.doFinal(message.toByteArray(charset("UTF-8")))
    return Base64.encodeToString(cryptedBytes, Base64.DEFAULT)
  }

  private fun getPublicKey(tag: String): PublicKey? {
    val keystore = KeyStore.getInstance(_androidKeyStore)
    keystore.load(null)
    val cert = keystore.getCertificate(tag)
    return cert.publicKey
  }

  private fun getPrivateKey(tag: String): Key? {
    val keystore = KeyStore.getInstance(_androidKeyStore)
    keystore.load(null)
    val entry = keystore.getEntry(tag, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      Log.w(tag, "Not an instance of a PrivateKeyEntry")
      throw Exception("Not an instance of a PrivateKeyEntry")
    } else {
      return entry.privateKey
    }
  }

  private fun generateKeyPair(tag: String): KeyPair {
    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, _androidKeyStore)

    generator.initialize(
            KeyGenParameterSpec.Builder(
                    tag, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, F4))
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512)
                    .setUserAuthenticationRequired(false)
                    .build())
    return generator.generateKeyPair()
  }

  private fun deleteKey(tag: String) {
    val keyStore: KeyStore = KeyStore.getInstance(_androidKeyStore)
    keyStore.load(null)
    keyStore.deleteEntry(tag)
  }
}
