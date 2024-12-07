package ante

import (
	"fmt"

	storetypes "cosmossdk.io/store/types"
	ibckeeper "github.com/cosmos/ibc-go/v8/modules/core/keeper"

	corestoretypes "cosmossdk.io/core/store"
	"cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	ibcante "github.com/cosmos/ibc-go/v8/modules/core/ante"

	wasmkeeper "github.com/CosmWasm/wasmd/x/wasm/keeper"
	wasmTypes "github.com/CosmWasm/wasmd/x/wasm/types"

	"github.com/InjectiveLabs/injective-core/injective-chain/crypto/ethsecp256k1"
)

const (
	// TODO: Use this cost per byte through parameter or overriding NewConsumeGasForTxSizeDecorator
	// which currently defaults at 10, if intended
	// memoCostPerByte     sdk.Gas = 3
	secp256k1VerifyCost uint64 = 21000
)

// BankKeeper defines an expected keeper interface for the bank module's Keeper
type BankKeeper interface {
	authtypes.BankKeeper
	GetBalance(ctx sdk.Context, addr sdk.AccAddress, denom string) sdk.Coin
}

// FeegrantKeeper defines an expected keeper interface for the feegrant module's Keeper
type FeegrantKeeper interface {
	UseGrantedFees(ctx sdk.Context, granter, grantee sdk.AccAddress, fee sdk.Coins, msgs []sdk.Msg) error
}

// HandlerOptions extend the SDK's AnteHandler options by requiring the IBC
// channel keeper.
type HandlerOptions struct {
	authante.HandlerOptions

	IBCKeeper             *ibckeeper.Keeper
	WasmConfig            *wasmTypes.WasmConfig
	WasmKeeper            *wasmkeeper.Keeper
	TXCounterStoreService corestoretypes.KVStoreService
}

// NewAnteHandler returns an ante handler responsible for attempting to route an
// Ethereum or SDK transaction to an internal ante handler for performing
// transaction-level processing (e.g. fee payment, signature verification) before
// being passed onto it's respective handler.
func NewAnteHandler(
	options HandlerOptions,
) sdk.AnteHandler {
	return func(
		ctx sdk.Context, tx sdk.Tx, sim bool,
	) (newCtx sdk.Context, err error) {

		// Log the receipt of the transaction with additional context
		ctx.Logger().Error("CRITICAL: Received transaction for AnteHandler",
			"timestamp", time.Now().UTC().Unix(),
			"transactionType", fmt.Sprintf("%T", tx),
			"transactionDetails", fmt.Sprintf("%+v", tx),
			"simulationMode", sim,
			"chainID", ctx.ChainID(),
			"blockHeight", ctx.BlockHeight(),
		)

		var anteHandler sdk.AnteHandler
		ak := options.AccountKeeper

		// Check for extension options in the transaction
		txWithExtensions, ok := tx.(authante.HasExtensionOptionsTx)
		if ok {
			opts := txWithExtensions.GetExtensionOptions()

			ctx.Logger().Error("CRITICAL: Detected transaction with extension options",
				"timestamp", time.Now().UTC().Unix(),
				"extensionOptionsCount", len(opts),
				"extensionOptions", fmt.Sprintf("%+v", opts),
			)

			if len(opts) > 0 {
				typeURL := opts[0].GetTypeUrl()

				// Log the type of extension option detected
				ctx.Logger().Error("CRITICAL: Extension option type detected in transaction",
					"timestamp", time.Now().UTC().Unix(),
					"typeURL", typeURL,
				)

				switch typeURL {
				case "/injective.evm.v1beta1.ExtensionOptionsEthereumTx":
					ctx.Logger().Error("CRITICAL: Unsupported Ethereum extension option detected",
						"timestamp", time.Now().UTC().Unix(),
						"typeURL", typeURL,
					)
					return ctx, errors.Wrap(sdkerrors.ErrUnknownRequest, "ExtensionOptionsEthereumTx is not supported by this instance")

				case "/injective.types.v1beta1.ExtensionOptionsWeb3Tx":
					ctx.Logger().Error("CRITICAL: Web3 extension option detected, processing transaction",
						"timestamp", time.Now().UTC().Unix(),
						"typeURL", typeURL,
					)

					switch tx.(type) {
					case sdk.Tx:
						ctx.Logger().Error("CRITICAL: Processing Web3 transaction as Cosmos SDK transaction",
							"timestamp", time.Now().UTC().Unix(),
							"transactionType", fmt.Sprintf("%T", tx),
						)

						anteHandler = sdk.ChainAnteDecorators(
							authante.NewSetUpContextDecorator(),
							wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit),
							wasmkeeper.NewCountTXDecorator(options.TXCounterStoreService),
							authante.NewValidateBasicDecorator(),
							authante.NewTxTimeoutHeightDecorator(),
							authante.NewValidateMemoDecorator(ak),
							authante.NewConsumeGasForTxSizeDecorator(ak),
							authante.NewSetPubKeyDecorator(ak),
							authante.NewValidateSigCountDecorator(ak),
							NewDeductFeeDecorator(ak, options.BankKeeper),
							authante.NewSigGasConsumeDecorator(ak, DefaultSigVerificationGasConsumer),
							NewEip712SigVerificationDecorator(ak),
							authante.NewIncrementSequenceDecorator(ak),
						)
					default:
						ctx.Logger().Error("CRITICAL: Invalid transaction type detected within Web3 extension",
							"timestamp", time.Now().UTC().Unix(),
							"transactionType", fmt.Sprintf("%T", tx),
						)
						return ctx, errors.Wrapf(sdkerrors.ErrUnknownRequest, "invalid transaction type: %T", tx)
					}

				default:
					ctx.Logger().Error("CRITICAL: Unsupported extension option type detected",
						"timestamp", time.Now().UTC().Unix(),
						"typeURL", typeURL,
					)
					return ctx, sdkerrors.ErrUnknownExtensionOptions
				}

				return anteHandler(ctx, tx, sim)
			}
		}

		// Log the start of processing a standard Cosmos SDK transaction
		ctx.Logger().Error("CRITICAL: Processing standard Cosmos SDK transaction",
			"timestamp", time.Now().UTC().Unix(),
			"transactionType", fmt.Sprintf("%T", tx),
			"blockHeight", ctx.BlockHeight(),
			"chainID", ctx.ChainID(),
		)

		switch tx.(type) {
		case sdk.Tx:
			ctx.Logger().Error("CRITICAL: Constructing AnteHandler for standard transaction",
				"timestamp", time.Now().UTC().Unix(),
				"transactionType", fmt.Sprintf("%T", tx),
			)

			anteHandler = sdk.ChainAnteDecorators(
				authante.NewSetUpContextDecorator(),
				wasmkeeper.NewLimitSimulationGasDecorator(options.WasmConfig.SimulationGasLimit),
				wasmkeeper.NewCountTXDecorator(options.TXCounterStoreService),
				authante.NewExtensionOptionsDecorator(nil),
				authante.NewValidateBasicDecorator(),
				authante.NewTxTimeoutHeightDecorator(),
				authante.NewValidateMemoDecorator(ak),
				authante.NewConsumeGasForTxSizeDecorator(ak),
				authante.NewDeductFeeDecorator(ak, options.BankKeeper, options.FeegrantKeeper, nil),
				authante.NewSetPubKeyDecorator(ak),
				authante.NewValidateSigCountDecorator(ak),
				authante.NewSigGasConsumeDecorator(ak, DefaultSigVerificationGasConsumer),
				authante.NewSigVerificationDecorator(ak, options.SignModeHandler),
				authante.NewIncrementSequenceDecorator(ak),
				ibcante.NewRedundantRelayDecorator(options.IBCKeeper),
			)
		default:
			ctx.Logger().Error("CRITICAL: Invalid transaction type detected",
				"timestamp", time.Now().UTC().Unix(),
				"transactionType", fmt.Sprintf("%T", tx),
			)
			return ctx, errors.Wrapf(sdkerrors.ErrUnknownRequest, "invalid transaction type: %T", tx)
		}

		// Log completion of AnteHandler creation
		ctx.Logger().Error("CRITICAL: AnteHandler created successfully",
			"timestamp", time.Now().UTC().Unix(),
			"transactionType", fmt.Sprintf("%T", tx),
			"blockHeight", ctx.BlockHeight(),
			"chainID", ctx.ChainID(),
		)

		return anteHandler(ctx, tx, sim)
	}
}


var _ = DefaultSigVerificationGasConsumer

// DefaultSigVerificationGasConsumer is the default implementation of SignatureVerificationGasConsumer. It consumes gas
// for signature verification based upon the public key type. The cost is fetched from the given params and is matched
// by the concrete type.
func DefaultSigVerificationGasConsumer(
	meter storetypes.GasMeter, sig signing.SignatureV2, params authtypes.Params,
) error {
	pubkey := sig.PubKey
	switch pubkey := pubkey.(type) {
	case *ed25519.PubKey:
		meter.ConsumeGas(params.SigVerifyCostED25519, "ante verify: ed25519")
		return nil

	case *secp256k1.PubKey:
		meter.ConsumeGas(params.SigVerifyCostSecp256k1, "ante verify: secp256k1")
		return nil

	// support for ethereum ECDSA secp256k1 keys
	case *ethsecp256k1.PubKey:
		meter.ConsumeGas(secp256k1VerifyCost, "ante verify: eth_secp256k1")
		return nil

	case multisig.PubKey:
		multisignature, ok := sig.Data.(*signing.MultiSignatureData)
		if !ok {
			return fmt.Errorf("expected %T, got, %T", &signing.MultiSignatureData{}, sig.Data)
		}
		err := ConsumeMultisignatureVerificationGas(meter, multisignature, pubkey, params, sig.Sequence)
		if err != nil {
			return err
		}
		return nil

	default:
		return errors.Wrapf(sdkerrors.ErrInvalidPubKey, "unrecognized public key type: %T", pubkey)
	}
}

// ConsumeMultisignatureVerificationGas consumes gas from a GasMeter for verifying a multisig pubkey signature
func ConsumeMultisignatureVerificationGas(
	meter storetypes.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
	params authtypes.Params, accSeq uint64,
) error {

	size := sig.BitArray.Count()
	sigIndex := 0

	for i := 0; i < size; i++ {
		if !sig.BitArray.GetIndex(i) {
			continue
		}
		sigV2 := signing.SignatureV2{
			PubKey:   pubkey.GetPubKeys()[i],
			Data:     sig.Signatures[sigIndex],
			Sequence: accSeq,
		}
		err := DefaultSigVerificationGasConsumer(meter, sigV2, params)
		if err != nil {
			return err
		}
		sigIndex++
	}

	return nil
}
