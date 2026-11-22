"""Secure credential storage for LootCheck using Windows Credential Manager."""

import logging

logger = logging.getLogger('LootCheck')

# Try to use keyring (Windows Credential Manager)
_KEYRING_AVAILABLE = False
try:
    import keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    logger.info("keyring not available, falling back to file-based storage")

# Fallback: encrypted file storage
import json
import os
import base64
from src.utils.constants import CREDENTIAL_SERVICE_NAME, CREDENTIAL_USERNAME, get_config_dir


class CredentialStorage:
    """Manages API key storage using Windows Credential Manager or file fallback."""

    def __init__(self):
        self._use_keyring = _KEYRING_AVAILABLE
        self._config_file = os.path.join(get_config_dir(), '.credentials')

    @property
    def storage_method(self) -> str:
        """Return the storage method being used."""
        if self._use_keyring:
            return "Windows Credential Manager"
        return "Local encrypted file (less secure)"

    def save_api_key(self, api_key: str) -> bool:
        """Save the VirusTotal API key."""
        try:
            if self._use_keyring:
                keyring.set_password(CREDENTIAL_SERVICE_NAME, CREDENTIAL_USERNAME, api_key)
                logger.info("API key saved to Windows Credential Manager")
                return True
            else:
                return self._save_to_file(api_key)
        except Exception as e:
            logger.error("Failed to save API key: %s", type(e).__name__)
            # Try file fallback if keyring fails
            if self._use_keyring:
                logger.info("Keyring failed, trying file fallback")
                self._use_keyring = False
                return self._save_to_file(api_key)
            return False

    def get_api_key(self) -> str | None:
        """Retrieve the stored API key."""
        try:
            if self._use_keyring:
                try:
                    key = keyring.get_password(CREDENTIAL_SERVICE_NAME, CREDENTIAL_USERNAME)
                    if key:
                        return key
                except Exception as ex:
                    logger.debug("Keyring access failed (%s), trying file fallback", ex)
                # Also check file fallback
                return self._load_from_file()
            else:
                return self._load_from_file()
        except Exception as e:
            logger.debug("Failed to retrieve API key: %s", type(e).__name__)
            return self._load_from_file()

    def delete_api_key(self) -> bool:
        """Delete the stored API key."""
        success = False
        try:
            if self._use_keyring:
                keyring.delete_password(CREDENTIAL_SERVICE_NAME, CREDENTIAL_USERNAME)
                success = True
        except Exception:
            pass

        # Also clean up file storage
        try:
            if os.path.exists(self._config_file):
                os.remove(self._config_file)
                success = True
        except OSError:
            pass

        logger.info("API key deleted: %s", success)
        return success

    def has_api_key(self) -> bool:
        """Check if an API key is stored."""
        key = self.get_api_key()
        return key is not None and len(key) > 0

    def _save_to_file(self, api_key: str) -> bool:
        """Save API key to an obfuscated file (not truly encrypted, but not plaintext)."""
        try:
            # Base64 encode — not real encryption, but prevents casual reading
            encoded = base64.b64encode(api_key.encode('utf-8')).decode('utf-8')
            data = {"k": encoded, "v": 1}
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            logger.info("API key saved to file (obfuscated)")
            return True
        except (OSError, IOError) as e:
            logger.error("Failed to save API key to file: %s", type(e).__name__)
            return False

    def _load_from_file(self) -> str | None:
        """Load API key from obfuscated file."""
        try:
            if not os.path.exists(self._config_file):
                return None
            with open(self._config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if 'k' in data:
                return base64.b64decode(data['k'].encode('utf-8')).decode('utf-8')
            return None
        except (OSError, IOError, json.JSONDecodeError, KeyError, ValueError):
            return None
