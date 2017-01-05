package vault

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/pgpkeys"
	"github.com/hashicorp/vault/shamir"
)

// unsealMetadataStorageEntry holds metadata about the unseal operation. This
// informaion is stored during the initialization and is fetched post unseal
// for auditing purposes.
type unsealMetadataStorageEntry struct {
	// Data is a map from the unseak key shard to its respective unique
	// identifier which can be audit logged.
	Data map[string]*unsealKeyMetadata `json:"data" structs:"data" mapstructure:"data"`
}

// unsealKeyMetadata holds metadata associated with a specific unseal key shard.
type unsealKeyMetadata struct {
	ID             string `json:"id" structs:"id" mapstructure:"id"`
	PGPFingerprint string `json:"pgp_fingerprint" structs:"pgp_fingerprint" mapstructure:"pgp_fingerprint"`
}

// InitParams keeps the init function from being littered with too many
// params, that's it!
type InitParams struct {
	BarrierConfig   *SealConfig
	RecoveryConfig  *SealConfig
	RootTokenPGPKey string
}

// InitResult is used to provide the key parts back after
// they are generated as part of the initialization.
type InitResult struct {
	SecretShares   [][]byte
	RecoveryShares [][]byte
	RootToken      string
}

// Initialized checks if the Vault is already initialized
func (c *Core) Initialized() (bool, error) {
	// Check the barrier first
	init, err := c.barrier.Initialized()
	if err != nil {
		c.logger.Error("core: barrier init check failed", "error", err)
		return false, err
	}
	if !init {
		c.logger.Info("core: security barrier not initialized")
		return false, nil
	}

	// Verify the seal configuration
	sealConf, err := c.seal.BarrierConfig()
	if err != nil {
		return false, err
	}
	if sealConf == nil {
		return false, fmt.Errorf("core: barrier reports initialized but no seal configuration found")
	}

	return true, nil
}

func (c *Core) generateShares(sc *SealConfig) ([]byte, [][]byte, [][]byte, []string, error) {
	// Generate a master key
	masterKeyBytes, err := c.barrier.GenerateKey()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("key generation failed: %v", err)
	}

	// Return the master key if only a single key part is used
	var unsealKeys [][]byte
	if sc.SecretShares == 1 {
		unsealKeys = append(unsealKeys, masterKeyBytes)
	} else {
		// Split the master key using the Shamir algorithm
		unsealKeys, err = shamir.Split(masterKeyBytes, sc.SecretShares, sc.SecretThreshold)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to generate barrier shares: %v", err)
		}
	}

	// If we have PGP keys, perform the encryption
	var encryptedUnsealKeys [][]byte
	var pgpFingerprints []string
	if len(sc.PGPKeys) > 0 {
		hexEncodedShares := make([][]byte, len(unsealKeys))
		for i, _ := range unsealKeys {
			hexEncodedShares[i] = []byte(hex.EncodeToString(unsealKeys[i]))
		}
		pgpFingerprints, encryptedUnsealKeys, err = pgpkeys.EncryptShares(hexEncodedShares, sc.PGPKeys)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	return masterKeyBytes, unsealKeys, encryptedUnsealKeys, pgpFingerprints, nil
}

// Initialize is used to initialize the Vault with the given
// configurations.
func (c *Core) Initialize(initParams *InitParams) (*InitResult, error) {
	barrierConfig := initParams.BarrierConfig
	recoveryConfig := initParams.RecoveryConfig

	if c.seal.RecoveryKeySupported() {
		if recoveryConfig == nil {
			return nil, fmt.Errorf("recovery configuration must be supplied")
		}

		if recoveryConfig.SecretShares < 1 {
			return nil, fmt.Errorf("recovery configuration must specify a positive number of shares")
		}

		// Check if the seal configuration is valid
		if err := recoveryConfig.Validate(); err != nil {
			c.logger.Error("core: invalid recovery configuration", "error", err)
			return nil, fmt.Errorf("invalid recovery configuration: %v", err)
		}
	}

	// Check if the seal configuration is valid
	if err := barrierConfig.Validate(); err != nil {
		c.logger.Error("core: invalid seal configuration", "error", err)
		return nil, fmt.Errorf("invalid seal configuration: %v", err)
	}

	// Avoid an initialization race
	c.stateLock.Lock()
	defer c.stateLock.Unlock()

	// Check if we are initialized
	init, err := c.Initialized()
	if err != nil {
		return nil, err
	}
	if init {
		return nil, ErrAlreadyInit
	}

	err = c.seal.Init()
	if err != nil {
		c.logger.Error("core: failed to initialize seal", "error", err)
		return nil, fmt.Errorf("error initializing seal: %v", err)
	}

	err = c.seal.SetBarrierConfig(barrierConfig)
	if err != nil {
		c.logger.Error("core: failed to save barrier configuration", "error", err)
		return nil, fmt.Errorf("barrier configuration saving failed: %v", err)
	}

	var returnedKeys [][]byte
	barrierKey, barrierUnsealKeys, barrierEncryptedUnsealKeys, barrierPGPFingerprints, err := c.generateShares(barrierConfig)
	if err != nil {
		c.logger.Error("core: error generating shares", "error", err)
		return nil, err
	}

	// Create metadata for the unseal keys generated using the unseal shards
	// created. But persist the metadata after the barrier is unsealed. Note
	// that the creation of metadata is performed before stored shares are
	// processed. This is done to ensure that the metadata contains entries for
	// all the unseal key shards.
	unsealMetadataEntry := &unsealMetadataStorageEntry{
		Data: make(map[string]*unsealKeyMetadata),
	}

	// Associate each unseal key shard with a UUID
	for i, unsealKeyShard := range barrierUnsealKeys {
		unsealKeyUUID, err := uuid.GenerateUUID()
		if err != nil {
			c.logger.Error("core: failed to generate unseal key identifier", "error", err)
			return nil, err
		}
		metadata := &unsealKeyMetadata{}
		if barrierEncryptedUnsealKeys != nil {
			metadata.PGPFingerprint = barrierPGPFingerprints[i]
		} else {
			metadata.ID = unsealKeyUUID
		}
		unsealMetadataEntry.Data[base64.StdEncoding.EncodeToString(unsealKeyShard)] = metadata
	}

	// JSON encode the unseal keys matadata
	unsealMetadataJSON, err := jsonutil.EncodeJSON(unsealMetadataEntry)
	if err != nil {
		c.logger.Error("core: failed to encode unseal metadata", "error", err)
		return nil, err
	}

	switch {
	case barrierEncryptedUnsealKeys != nil:
		returnedKeys = barrierEncryptedUnsealKeys
	default:
		returnedKeys = barrierUnsealKeys
	}

	// If we are storing shares, pop them out of the returned results and push
	// them through the seal
	if barrierConfig.StoredShares > 0 {
		if len(barrierConfig.PGPKeys) > 0 {
			c.logger.Error("core: PGP keys not supported when storing shares")
			return nil, fmt.Errorf("PGP keys not supported when storing shares")
		}

		var keysToStore [][]byte
		for i := 0; i < barrierConfig.StoredShares; i++ {
			keysToStore = append(keysToStore, returnedKeys[0])
			returnedKeys = returnedKeys[1:]
		}
		if err := c.seal.SetStoredKeys(keysToStore); err != nil {
			c.logger.Error("core: failed to store keys", "error", err)
			return nil, fmt.Errorf("failed to store keys: %v", err)
		}
	}

	results := &InitResult{
		SecretShares: returnedKeys,
	}

	// Initialize the barrier
	if err := c.barrier.Initialize(barrierKey); err != nil {
		c.logger.Error("core: failed to initialize barrier", "error", err)
		return nil, fmt.Errorf("failed to initialize barrier: %v", err)
	}
	if c.logger.IsInfo() {
		c.logger.Info("core: security barrier initialized", "shares", barrierConfig.SecretShares, "threshold", barrierConfig.SecretThreshold)
	}

	// Unseal the barrier
	if err := c.barrier.Unseal(barrierKey); err != nil {
		c.logger.Error("core: failed to unseal barrier", "error", err)
		return nil, fmt.Errorf("failed to unseal barrier: %v", err)
	}

	// Ensure the barrier is re-sealed
	defer func() {
		if err := c.barrier.Seal(); err != nil {
			c.logger.Error("core: failed to seal barrier", "error", err)
		}
	}()

	// Persist the unseal metadata
	err = c.barrier.Put(&Entry{
		Key:   coreUnsealMetadataPath,
		Value: unsealMetadataJSON,
	})
	if err != nil {
		c.logger.Error("core: failed to store unseal metadata", "error", err)
		return nil, err
	}

	// Perform initial setup
	if err := c.setupCluster(); err != nil {
		c.stateLock.Unlock()
		c.logger.Error("core: cluster setup failed during init", "error", err)
		return nil, err
	}
	if err := c.postUnseal(); err != nil {
		c.logger.Error("core: post-unseal setup failed during init", "error", err)
		return nil, err
	}

	// Save the configuration regardless, but only generate a key if it's not
	// disabled. When using recovery keys they are stored in the barrier, so
	// this must happen post-unseal.
	if c.seal.RecoveryKeySupported() {
		err = c.seal.SetRecoveryConfig(recoveryConfig)
		if err != nil {
			c.logger.Error("core: failed to save recovery configuration", "error", err)
			return nil, fmt.Errorf("recovery configuration saving failed: %v", err)
		}

		if recoveryConfig.SecretShares > 0 {
			recoveryKey, recoveryUnsealKeys, recoveryEncryptedUnsealKeys, _, err := c.generateShares(recoveryConfig)
			if err != nil {
				c.logger.Error("core: failed to generate recovery shares", "error", err)
				return nil, err
			}

			err = c.seal.SetRecoveryKey(recoveryKey)
			if err != nil {
				return nil, err
			}

			switch {
			case recoveryEncryptedUnsealKeys != nil:
				results.RecoveryShares = recoveryEncryptedUnsealKeys
			default:
				results.RecoveryShares = recoveryUnsealKeys
			}

			results.RecoveryShares = recoveryUnsealKeys
		}
	}

	// Generate a new root token
	rootToken, err := c.tokenStore.rootToken()
	if err != nil {
		c.logger.Error("core: root token generation failed", "error", err)
		return nil, err
	}
	results.RootToken = rootToken.ID
	c.logger.Info("core: root token generated")

	if initParams.RootTokenPGPKey != "" {
		_, encryptedVals, err := pgpkeys.EncryptShares([][]byte{[]byte(results.RootToken)}, []string{initParams.RootTokenPGPKey})
		if err != nil {
			c.logger.Error("core: root token encryption failed", "error", err)
			return nil, err
		}
		results.RootToken = base64.StdEncoding.EncodeToString(encryptedVals[0])
	}

	// Prepare to re-seal
	if err := c.preSeal(); err != nil {
		c.logger.Error("core: pre-seal teardown failed", "error", err)
		return nil, err
	}

	return results, nil
}

func (c *Core) UnsealWithStoredKeys() error {
	if !c.seal.StoredKeysSupported() {
		return nil
	}

	sealed, err := c.Sealed()
	if err != nil {
		c.logger.Error("core: error checking sealed status in auto-unseal", "error", err)
		return fmt.Errorf("error checking sealed status in auto-unseal: %s", err)
	}
	if !sealed {
		return nil
	}

	c.logger.Info("core: stored unseal keys supported, attempting fetch")
	keys, err := c.seal.GetStoredKeys()
	if err != nil {
		c.logger.Error("core: fetching stored unseal keys failed", "error", err)
		return &NonFatalError{Err: fmt.Errorf("fetching stored unseal keys failed: %v", err)}
	}
	if len(keys) == 0 {
		c.logger.Warn("core: stored unseal key(s) supported but none found")
	} else {
		unsealed := false
		keysUsed := 0
		for _, key := range keys {
			unsealed, err = c.Unseal(key)
			if err != nil {
				c.logger.Error("core: unseal with stored unseal key failed", "error", err)
				return &NonFatalError{Err: fmt.Errorf("unseal with stored key failed: %v", err)}
			}
			keysUsed += 1
			if unsealed {
				break
			}
		}
		if !unsealed {
			if c.logger.IsWarn() {
				c.logger.Warn("core: stored unseal key(s) used but Vault not unsealed yet", "stored_keys_used", keysUsed)
			}
		} else {
			if c.logger.IsInfo() {
				c.logger.Info("core: successfully unsealed with stored key(s)", "stored_keys_used", keysUsed)
			}
		}
	}

	return nil
}
