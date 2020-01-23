package lib

import "strings"

// RuleError is an error type that specifies an error occurred during
// block processing that is related to a consensus rule. By checking the
// type of the error the caller can determine that the error was due to
// a consensus rule and determine which consensus rule caused the issue.
type RuleError string

const (
	RuleErrorDuplicateBlock                                        RuleError = "RuleErrorDuplicateBlock"
	RuleErrorDuplicateOrphan                                       RuleError = "RuleErrorDuplicateOrphan"
	RuleErrorMinDifficulty                                         RuleError = "RuleErrorMinDifficulty"
	RuleErrorBlockTooBig                                           RuleError = "RuleErrorBlockTooBig"
	RuleErrorNoTxns                                                RuleError = "RuleErrorNoTxns"
	RuleErrorFirstTxnMustBeBlockReward                             RuleError = "RuleErrorFirstTxnMustBeBlockReward"
	RuleErrorMoreThanOneBlockReward                                RuleError = "RuleErrorMoreThanOneBlockReward"
	RuleErrorPreviousBlockInvalid                                  RuleError = "RuleErrorPreviousBlockInvalid"
	RuleErrorPreviousBlockHeaderInvalid                            RuleError = "RuleErrorPreviousBlockHeaderInvalid"
	RuleErrorTxnMustHaveAtLeastOneInput                            RuleError = "RuleErrorTxnMustHaveAtLeastOneInput"
	RuleErrorTxnMustHaveAtLeastOneOutput                           RuleError = "RuleErrorTxnMustHaveAtLeastOneOutput"
	RuleErrorOutputExceedsMax                                      RuleError = "RuleErrorOutputExceedsMax"
	RuleErrorOutputOverflowsTotal                                  RuleError = "RuleErrorOutputOverflowsTotal"
	RuleErrorTotalOutputExceedsMax                                 RuleError = "RuleErrorTotalOutputExceedsMax"
	RuleErrorDuplicateInputs                                       RuleError = "RuleErrorDuplicateInputs"
	RuleErrorInvalidTxnMerkleRoot                                  RuleError = "RuleErrorInvalidTxnMerkleRoot"
	RuleErrorDuplicateTxn                                          RuleError = "RuleErrorDuplicateTxn"
	RuleErrorInputSpendsNonexistentUtxo                            RuleError = "RuleErrorInputSpendsNonexistentUtxo"
	RuleErrorInputSpendsPreviouslySpentOutput                      RuleError = "RuleErrorInputSpendsPreviouslySpentOutput"
	RuleErrorInputSpendsImmatureBlockReward                        RuleError = "RuleErrorInputSpendsImmatureBlockReward"
	RuleErrorInputSpendsOutputWithInvalidAmount                    RuleError = "RuleErrorInputSpendsOutputWithInvalidAmount"
	RuleErrorTxnOutputWithInvalidAmount                            RuleError = "RuleErrorTxnOutputWithInvalidAmount"
	RuleErrorTxnOutputExceedsInput                                 RuleError = "RuleErrorTxnOutputExceedsInput"
	RuleErrorBlockRewardOutputWithInvalidAmount                    RuleError = "RuleErrorBlockRewardOutputWithInvalidAmount"
	RuleErrorBlockRewardOverflow                                   RuleError = "RuleErrorBlockRewardOverflow"
	RuleErrorBlockRewardExceedsMaxAllowed                          RuleError = "RuleErrorBlockRewardExceedsMaxAllowed"
	RuleErrorMerchantUsernameExists                                RuleError = "RuleErrorMerchantUsernameExists"
	RuleErrorMerchantPkExists                                      RuleError = "RuleErrorMerchantPkExists"
	RuleErrorPubKeyLen                                             RuleError = "RuleErrorPubKeyLen"
	RuleErrorUsernameLen                                           RuleError = "RuleErrorUsernameLen"
	RuleErrorMerchantDescriptionLen                                RuleError = "RuleErrorMerchantDescriptionLen"
	RuleErrorEncryptedDataLen                                      RuleError = "RuleErrorEncryptedDataLen"
	RuleErrorBadOrderID                                            RuleError = "RuleErrorBadOrderID"
	RuleErrorReviewLen                                             RuleError = "RuleErrorReviewLen"
	RuleErrorInputOverflows                                        RuleError = "RuleErrorInputOverflows"
	RuleErrorInsufficientRefund                                    RuleError = "RuleErrorInsufficientRefund"
	RuleErrorMissingMerchantForOrder                               RuleError = "RuleErrorMissingMerchantForOrder"
	RuleErrorBuyerMessageHash                                      RuleError = "RuleErrorBuyerMessageHash"
	RuleErrorRejectReasonLen                                       RuleError = "RuleErrorRejectReasonLen"
	RuleErrorRejectReasonHash                                      RuleError = "RuleErrorRejectReasonHash"
	RuleErrorFulfillingOrderTooSoon                                RuleError = "RuleErrorFulfillingOrderTooSoon"
	RuleErrorBadMerchantID                                         RuleError = "RuleErrorBadMerchantID"
	RuleErrorNonexistentMerchant                                   RuleError = "RuleErrorNonexistentMerchant"
	RuleErrorReviewTextHash                                        RuleError = "RuleErrorReviewTextHash"
	RuleErrorMissingSignature                                      RuleError = "RuleErrorMissingSignature"
	RuleErrorSigHash                                               RuleError = "RuleErrorSigHash"
	RuleErrorParsePublicKey                                        RuleError = "RuleErrorParsePublicKey"
	RuleErrorSigCheckFailed                                        RuleError = "RuleErrorSigCheckFailed"
	RuleErrorOutputPublicKeyNotRecognized                          RuleError = "RuleErrorOutputPublicKeyNotRecognized"
	RuleErrorInputsWithDifferingSpendKeys                          RuleError = "RuleErrorInputsWithDifferingSpendKeys"
	RuleErrorInvalidTransactionSignature                           RuleError = "RuleErrorInvalidTransactionSignature"
	RuleErrorInvalidBlockHeader                                    RuleError = "RuleErrorInvalidBlockHeader"
	RuleErrorOrphanBlock                                           RuleError = "RuleErrorOrphanBlock"
	RuleErrorTxnPublicKeyDiffersFromMerchantPublicKey              RuleError = "RuleErrorTxnPublicKeyDiffersFromMerchantPublicKey"
	RuleErrorOrderBeingCanceledNotInPlacedState                    RuleError = "RuleErrorOrderBeingCanceledNotInPlacedState"
	RuleErrorOnlyBuyerCanCancelOrder                               RuleError = "RuleErrorOnlyBuyerCanCancelOrder"
	RuleErrorRejectTransactionMustBeSignedByMerchant               RuleError = "RuleErrorRejectTransactionMustBeSignedByMerchant"
	RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey           RuleError = "RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey"
	RuleErrorBlockRewardTxnNotAllowedToHaveInputs                  RuleError = "RuleErrorBlockRewardTxnNotAllowedToHaveInputs"
	RuleErrorBlockRewardTxnNotAllowedToHaveSignature               RuleError = "RuleErrorBlockRewardTxnNotAllowedToHaveSignature"
	RuleErrorConfirmTransactionMustBeSignedByMerchant              RuleError = "RuleErrorConfirmTransactionMustBeSignedByMerchant"
	RuleErrorCommissionRevenueOverflow                             RuleError = "RuleErrorCommissionRevenueOverflow"
	RuleErrorOrderBeingConfirmedNotInPlacedState                   RuleError = "RuleErrorOrderBeingConfirmedNotInPlacedState"
	RuleErrorReviewingOrderNotInPlacedOrFulfilledOrReviewedState   RuleError = "RuleErrorReviewingOrderNotInPlacedOrFulfilledOrReviewedState"
	RuleErrorOnlyBuyerCanReviewOrder                               RuleError = "RuleErrorOnlyBuyerCanReviewOrder"
	RuleErrorFulfillingOrderNotInConfirmedState                    RuleError = "RuleErrorFulfillingOrderNotInConfirmedState"
	RuleErrorOnlyMerchantCanFulfillOrder                           RuleError = "RuleErrorOnlyMerchantCanFulfillOrder"
	RuleErrorRefundingOrderNotInStateConfirmedOrReviewdOrFulfilled RuleError = "RuleErrorRefundingOrderNotInStateConfirmedOrReviewdOrFulfilled"
	RuleErrorOnlyMerchantCanRefundOrder                            RuleError = "RuleErrorOnlyMerchantCanRefundOrder"
	RuleErrorUpdateMerchantRequiresNonZeroInput                    RuleError = "RuleErrorUpdateMerchantRequiresNonZeroInput"
	RuleErrorReviewOrderRequiresNonZeroInput                       RuleError = "RuleErrorReviewOrderRequiresNonZeroInput"
	RuleErrorBitcoinExchangeShouldNotHaveInputs                    RuleError = "RuleErrorBitcoinExchangeShouldNotHaveInputs"
	RuleErrorBitcoinExchangeShouldNotHaveOutputs                   RuleError = "RuleErrorBitcoinExchangeShouldNotHaveOutputs"
	RuleErrorBitcoinExchangeShouldNotHavePublicKey                 RuleError = "RuleErrorBitcoinExchangeShouldNotHavePublicKey"
	RuleErrorBitcoinExchangeShouldNotHaveSignature                 RuleError = "RuleErrorBitcoinExchangeShouldNotHaveSignature"
	RuleErrorBitcoinExchangeHasBadBitcoinTxHash                    RuleError = "RuleErrorBitcoinExchangeHasBadBitcoinTxHash"
	RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction       RuleError = "RuleErrorBitcoinExchangeDoubleSpendingBitcoinTransaction"
	RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain    RuleError = "RuleErrorBitcoinExchangeBlockHashNotFoundInMainBitcoinChain"
	RuleErrorBitcoinExchangeHasBadMerkleRoot                       RuleError = "RuleErrorBitcoinExchangeHasBadMerkleRoot"
	RuleErrorBitcoinExchangeInvalidMerkleProof                     RuleError = "RuleErrorBitcoinExchangeInvalidMerkleProof"
	RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs         RuleError = "RuleErrorBitcoinExchangeValidPublicKeyNotFoundInInputs"
	RuleErrorBitcoinExchangeProblemComputingBurnOutput             RuleError = "RuleErrorBitcoinExchangeProblemComputingBurnOutput"
	RuleErrorBitcoinExchangeFeeOverflow                            RuleError = "RuleErrorBitcoinExchangeFeeOverflow"
	RuleErrorBitcoinExchangeTotalOutputLessThanOrEqualZero         RuleError = "RuleErrorBitcoinExchangeTotalOutputLessThanOrEqualZero"
	RuleErrorTxnSanity                                             RuleError = "RuleErrorTxnSanity"
	RuleErrorTxnTooBig                                             RuleError = "RuleErrorTxnTooBig"
	RuleErrorPrivateMessageEncryptedTextLengthExceedsMax           RuleError = "RuleErrorPrivateMessageEncryptedTextLengthExceedsMax"
	RuleErrorPrivateMessageRecipientPubKeyLen                      RuleError = "RuleErrorPrivateMessageRecipientPubKeyLen"
	RuleErrorPrivateMessageTstampIsZero                            RuleError = "RuleErrorPrivateMessageTstampIsZero"
	RuleErrorTransactionMissingPublicKey                           RuleError = "RuleErrorTransactionMissingPublicKey"
	RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple    RuleError = "RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple"
	RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple RuleError = "RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple"
	RuleErrorPrivateMessageParsePubKeyError                        RuleError = "RuleErrorPrivateMessageParsePubKeyError"
	RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey RuleError = "RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey"
	RuleErrorInvalidMerchantMerkleRoot                             RuleError = "RuleErrorInvalidMerchantMerkleRoot"

	HeaderErrorDuplicateHeader                                                   RuleError = "HeaderErrorDuplicateHeader"
	HeaderErrorNilPrevHash                                                       RuleError = "HeaderErrorNilPrevHash"
	HeaderErrorInvalidParent                                                     RuleError = "HeaderErrorInvalidParent"
	HeaderErrorBlockTooFarInTheFuture                                            RuleError = "HeaderErrorBlockTooFarInTheFuture"
	HeaderErrorTimestampTooEarly                                                 RuleError = "HeaderErrorTimestampTooEarly"
	HeaderErrorBlockDifficultyAboveTarget                                        RuleError = "HeaderErrorBlockDifficultyAboveTarget"
	HeaderErrorHeightInvalid                                                     RuleError = "HeaderErrorHeightInvalid"
	HeaderErrorDifficultyBitsNotConsistentWithTargetDifficultyComputedFromParent RuleError = "HeaderErrorDifficultyBitsNotConsistentWithTargetDifficultyComputedFromParent"

	// For processing merchant KV data.
	MerchantErrorKeyNotFound RuleError = "MerchantErrorKeyNotFound"

	ListingErrorInvalidListingIndex                                  RuleError = "ListingErrorInvalidListingIndex"
	ListingErrorInvalidMerchantID                                    RuleError = "ListingErrorInvalidMerchantID"
	ListingErrorMerchantPublicKeyDoesNotMatch                        RuleError = "ListingErrorMerchantPublicKeyDoesNotMatch"
	ListingErrorLaterListingWithSameKeyExists                        RuleError = "ListingErrorLaterListingWithSameKeyExists"
	ListingErrorMaxListingSizeExceeded                               RuleError = "ListingErrorMaxListingSizeExceeded"
	ListingErrorMaximumStorageForMerchantExceeded                    RuleError = "ListingErrorMaximumStorageForMerchantExceeded"
	ListingErrorTitleTooLong                                         RuleError = "ListingErrorTitleTooLong"
	ListingErrorBodyTooLong                                          RuleError = "ListingErrorBodyTooLong"
	ListingErrorCategoryTooLong                                      RuleError = "ListingErrorCategoryTooLong"
	ListingErrorTitleTooShort                                        RuleError = "ListingErrorTitleTooShort"
	ListingErrorBodyTooShort                                         RuleError = "ListingErrorBodyTooShort"
	ListingErrorCategoryTooShort                                     RuleError = "ListingErrorCategoryTooShort"
	ListingErrorUnitNameSingularTooShort                             RuleError = "ListingErrorUnitNameSingularTooShort"
	ListingErrorUnitNamePluralTooShort                               RuleError = "ListingErrorUnitNamePluralTooShort"
	ListingErrorNotTopMerchantUnauthorizedToPostListing              RuleError = "ListingErrorNotTopMerchantUnauthorizedToPostListing"
	ListingErrorMerchantEntryNotFoundForMerchantID                   RuleError = "ListingErrorMerchantEntryNotFoundForMerchantID"
	ListingErrorMoreRecentListingWithSameIndexExists                 RuleError = "ListingErrorMoreRecentListingWithSameIndexExists"
	ListingErrorCouldNotSerializeListingToBytes                      RuleError = "ListingErrorCouldNotSerializeListingToBytes"
	ListingErrorAddingListingWouldCauseMaxMerchantStorageToBeEceeded RuleError = "ListingErrorAddingListingWouldCauseMaxMerchantStorageToBeEceeded"
	ListingErrorCouldNotSerializeTransactionWithoutSignature         RuleError = "ListingErrorCouldNotSerializeTransactionWithoutSignature"
	ListingErrorCouldNotParsePublicKey                               RuleError = "ListingErrorCouldNotParsePublicKey"
	ListingErrorSignatureNotValid                                    RuleError = "ListingErrorSignatureNotValid"
	ListingErrorListingExceedsMaxSize                                RuleError = "ListingErrorListingExceedsMaxSize"
	ListingErrorQuantityConflict                                     RuleError = "ListingErrorQuantityConflict"
	ListingErrorThumbnailRequired                                    RuleError = "ListingErrorThumbnailRequired"
	ListingErrorAtLeastOneImageRequired                              RuleError = "ListingErrorAtLeastOneImageRequired"

	TxErrorTooLarge                                                 RuleError = "TxErrorTooLarge"
	TxErrorDuplicate                                                RuleError = "TxErrorDuplicate"
	TxErrorDoubleSpend                                              RuleError = "TxErrorDoubleSpend"
	TxErrorIndividualBlockReward                                    RuleError = "TxErrorIndividualBlockReward"
	TxErrorInsufficientFeeMinFee                                    RuleError = "TxErrorInsufficientFeeMinFee"
	TxErrorInsufficientFeeRateLimit                                 RuleError = "TxErrorInsufficientFeeRateLimit"
	TxErrorInsufficientFeePriorityQueue                             RuleError = "TxErrorInsufficientFeePriorityQueue"
	TxErrorOrphanNotAllowed                                         RuleError = "TxErrorOrphanNotAllowed"
	TxErrorCannotProcessBitcoinExchangeUntilBitcoinManagerIsCurrent RuleError = "TxErrorCannotProcessBitcoinExchangeUntilBitcoinManagerIsCurrent"
)

// Error ...
func (e RuleError) Error() string {
	return string(e)
}

// IsRuleError returns true if the error is any of the errors specified above.
func IsRuleError(err error) bool {
	// TODO: I know I am a bad person for doing a string comparison here, but I
	// realized late in the game that errors.Wrapf warps the type of what it contains
	// and moving this from a type-switch to a string compare is easier than going
	// back and expunging all instances of Wrapf that might cause us to lose the
	// type of RuleError randomly as the error gets passed up the stack. Nevertheless,
	// eventually we should clean this up and get rid of the string comparison both
	// for the code's sake but also for the sake of our tests.
	return (strings.Contains(err.Error(), "RuleError") ||
		strings.Contains(err.Error(), "HeaderError") ||
		strings.Contains(err.Error(), "MerchantError") ||
		strings.Contains(err.Error(), "ListingError") ||
		strings.Contains(err.Error(), "TxError"))
}
