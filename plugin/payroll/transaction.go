package payroll

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/vultisig/plugin/common"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	gcommon "github.com/ethereum/go-ethereum/common"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"
)

// TODO: remove once the plugin installation is implemented
const (
	hexEncryptionKey = "hexencryptionkey"
)

func (p *PayrollPlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	var txs []vtypes.PluginKeysignRequest
	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return txs, fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	var payrollPolicy PayrollPolicy
	if err := json.Unmarshal(policy.Policy, &payrollPolicy); err != nil {
		return txs, fmt.Errorf("fail to unmarshal payroll policy, err: %w", err)
	}

	chain := vcommon.Ethereum

	for i, recipient := range payrollPolicy.Recipients {
		txHash, rawTx, err := p.generatePayrollTransaction(
			recipient.Amount,
			recipient.Address,
			payrollPolicy.ChainID[i],
			payrollPolicy.TokenID[i],
			policy.PublicKey,
			"",
			chain.GetDerivePath(),
		)
		fmt.Printf("Chain ID TEST 1: %s\n", payrollPolicy.ChainID[i])
		if err != nil {
			return []vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to generate transaction hash: %v", err)
		}

		// Create signing request
		signRequest := vtypes.PluginKeysignRequest{
			KeysignRequest: vtypes.KeysignRequest{
				PublicKey:        policy.PublicKey,
				Messages:         []string{hex.EncodeToString(txHash)},
				SessionID:        uuid.New().String(),
				HexEncryptionKey: hexEncryptionKey,
				DerivePath:       chain.GetDerivePath(),
				IsECDSA:          !chain.IsEdDSA(),
				PluginID:         policy.PluginID.String(),
			},
			Transaction: hex.EncodeToString(rawTx),

			PolicyID: policy.ID.String(),
		}
		txs = append(txs, signRequest)
	}

	signRequest := txs[0]
	txBytes, err := hex.DecodeString(signRequest.Transaction)
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to decode transaction hex: %w", err)
	}
	// unmarshal tx from sign req.transaction
	tx := &gtypes.Transaction{}
	err = tx.UnmarshalBinary(txBytes)
	if err != nil {
		p.logger.Errorf("Failed to unmarshal transaction: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to unmarshal transaction: %w:", err)
	}
	fmt.Printf("Chain ID TEST 2: %s\n", tx.ChainId().String())
	fmt.Printf("len TEST 2: %d\n", len(txs))

	return txs, nil
}

func (p *PayrollPlugin) generatePayrollTransaction(amountString, recipientString, chainID, tokenID, publicKey, chainCodeHex, derivePath string) ([]byte, []byte, error) {
	amount := new(big.Int)
	amount.SetString(amountString, 10)
	recipient := gcommon.HexToAddress(recipientString)

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ABI: %v", err)
	}

	inputData, err := parsedABI.Pack("transfer", recipient, amount)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack transfer data: %v", err)
	}

	// create call message to estimate gas
	callMsg := ethereum.CallMsg{
		From:  recipient, // todo : this works, but maybe better to put the correct sender address once we have it
		To:    &recipient,
		Data:  inputData,
		Value: big.NewInt(0),
	}
	// estimate gas limit
	gasLimit, err := p.rpcClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to estimate gas: %v", err)
	}
	// Use config values for gas calculations
	gasLimit = gasLimit * uint64(p.config.Gas.LimitMultiplier) / 100
	// get suggested gas price
	gasPrice, err := p.rpcClient.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get gas price: %v", err)
	}
	gasPrice = new(big.Int).Mul(gasPrice, big.NewInt(int64(p.config.Gas.PriceMultiplier)))
	// Parse chain ID
	chainIDInt := new(big.Int)
	chainIDInt.SetString(chainID, 10)
	fmt.Printf("Chain ID TEST 3: %s\n", chainIDInt.String())

	derivedAddress, err := common.DeriveAddress(publicKey, chainCodeHex, derivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive address: %v", err)
	}

	nextNonce, err := p.GetNextNonce(derivedAddress.Hex())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nonce: %v", err)
	}

	// Create unsigned transaction data
	V := new(big.Int).Set(chainIDInt)
	V = V.Mul(V, big.NewInt(2))
	V = V.Add(V, big.NewInt(35))
	txData := []interface{}{
		nextNonce,                     // nonce
		gasPrice,                      // gas price
		gasLimit,                      // gas limit
		gcommon.HexToAddress(tokenID), // to
		big.NewInt(0),                 // value
		inputData,                     // data
		V,                             // chain id
		uint(0),                       // empty v
		uint(0),                       // empty r
	}

	// Log each component separately
	p.logger.WithFields(logrus.Fields{
		"nonce":     txData[0],
		"gas_price": txData[1].(*big.Int).String(),
		"gas_limit": txData[2],
		"to":        txData[3].(gcommon.Address).Hex(),
		"value":     txData[4].(*big.Int).String(),
		"data_hex":  hex.EncodeToString(txData[5].([]byte)),
		"empty_v":   txData[6],
		"empty_r":   txData[7],
		"recipient": recipient.Hex(),
		"amount":    amount.String(),
	}).Info("Transaction components")

	rawTx, err := rlp.EncodeToBytes(txData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to RLP encode transaction: %v", err)
	}

	signer := gtypes.NewEIP155Signer(chainIDInt)
	tx := gtypes.NewTransaction(nextNonce, gcommon.HexToAddress(tokenID), big.NewInt(0), gasLimit, gasPrice, inputData)
	txHash := signer.Hash(tx).Bytes()

	p.logger.WithFields(logrus.Fields{
		"raw_tx_hex":   hex.EncodeToString(rawTx),
		"hash_to_sign": hex.EncodeToString(txHash),
	}).Info("Final transaction data")

	/*txBytes, err := hex.DecodeString(string(rawTx))
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return []types.PluginKeysignRequest{}, fmt.Errorf("failed to decode transaction hex: %w", err)
	}*/
	// unmarshal tx from sign req.transaction
	txCheck := &gtypes.Transaction{}
	err = rlp.DecodeBytes(rawTx, txCheck)
	if err != nil {
		p.logger.Errorf("Failed to RLP decode transaction: %v", err)
		return nil, nil, fmt.Errorf("failed to RLP decode transaction: %v: %w", err, asynq.SkipRetry)
	}
	fmt.Printf("Chain ID TEST 4: %s\n", txCheck.ChainId().String())

	return txHash, rawTx, nil
}

func (p *PayrollPlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	R, S, V, originalTx, chainID, _, err := p.convertData(signature, signRequest, policy)
	if err != nil {
		return fmt.Errorf("failed to convert R and S: %v", err)
	}

	innerTx := &gtypes.LegacyTx{
		Nonce:    originalTx.Nonce(),
		GasPrice: originalTx.GasPrice(),
		Gas:      originalTx.Gas(),
		To:       originalTx.To(),
		Value:    originalTx.Value(),
		Data:     originalTx.Data(),
		V:        V,
		R:        R,
		S:        S,
	}

	signedTx := gtypes.NewTx(innerTx)
	signer := gtypes.NewLondonSigner(chainID)
	sender, err := signer.Sender(signedTx)
	if err != nil {
		p.logger.WithError(err).Warn("Could not determine sender")
	} else {
		p.logger.WithField("sender", sender.Hex()).Info("Transaction sender")
	}

	// Check if RPC client is initialized
	if p.rpcClient == nil {
		return fmt.Errorf("RPC client not initialized")
	}

	err = p.rpcClient.SendTransaction(ctx, signedTx)
	if err != nil {
		p.logger.WithError(err).Error("Failed to broadcast transaction")
		return p.handleBroadcastError(err, sender)
	}

	p.logger.WithField("hash", signedTx.Hash().Hex()).Info("Transaction successfully broadcast")

	return p.monitorTransaction(signedTx)
}

func (p *PayrollPlugin) convertData(signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) (R *big.Int, S *big.Int, V *big.Int, originalTx *gtypes.Transaction, chainID *big.Int, recoveryID int64, err error) {
	// convert R and S from hex strings to big.Int
	R = new(big.Int)
	R.SetString(signature.R, 16)
	if R == nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse R value")
	}

	S = new(big.Int)
	S.SetString(signature.S, 16)
	if S == nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse S value")
	}

	// Decode the hex string to bytes first
	txBytes, err := hex.DecodeString(signRequest.Transaction)
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to decode transaction hex: %w", err)
	}

	originalTx = new(gtypes.Transaction)
	if err := rlp.DecodeBytes(txBytes, originalTx); err != nil {
		p.logger.Errorf("Failed to unmarshal transaction: %v", err)
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	policybytes := policy.Policy
	payrollPolicy := PayrollPolicy{}
	err = json.Unmarshal(policybytes, &payrollPolicy)
	if err != nil {
		p.logger.Errorf("Failed to unmarshal policy: %v", err)
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	chainID = new(big.Int)
	chainID.SetString(payrollPolicy.ChainID[0], 10)

	/*chainID = originalTx.ChainId()
	fmt.Printf("Chain ID TEST: %s\n", chainID.String())*/

	// calculate V according to EIP-155
	recoveryID, err = strconv.ParseInt(signature.RecoveryID, 10, 64)
	if err != nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse recovery ID: %w", err)
	}

	V = new(big.Int).Set(chainID)
	V.Mul(V, big.NewInt(2))
	V.Add(V, big.NewInt(35+recoveryID))

	return R, S, V, originalTx, chainID, recoveryID, nil
}
