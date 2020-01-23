package lib

import (
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
)

// supply.go defines all of the logic regarding the Ultra supply schedule. It also
// defines the Bitcoin <-> Ultra exchange schedule.

type MiningSupplyIntervalStart struct {
	StartBlockHeight uint32
	BlockRewardNanos uint64
}

type PurchaseSupplyIntervalStart struct {
	// How much each unit costs to purchase in Satoshis.
	SatoshisPerUnit uint64
	// The total supply cutoff at which this price applies.
	SupplyStartNanos uint64
}

const (
	NanosPerUnit  = uint64(1000000000)
	BlocksPerYear = uint32(6 * 24 * 365)
)

var (
	MiningSupplyIntervals = []*MiningSupplyIntervalStart{
		&MiningSupplyIntervalStart{
			StartBlockHeight: 0,
			BlockRewardNanos: 2 * NanosPerUnit,
		},
		&MiningSupplyIntervalStart{
			StartBlockHeight: 1 * BlocksPerYear,
			BlockRewardNanos: 1 * NanosPerUnit,
		},
		&MiningSupplyIntervalStart{
			StartBlockHeight: 3 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 2,
		},
		&MiningSupplyIntervalStart{
			StartBlockHeight: 7 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 4,
		},
		&MiningSupplyIntervalStart{
			StartBlockHeight: 15 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 10,
		},
		&MiningSupplyIntervalStart{
			StartBlockHeight: 32 * BlocksPerYear,
			BlockRewardNanos: 0,
		},
	}

	PurchaseSupplyIntervals = []*PurchaseSupplyIntervalStart{
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 0,
			SatoshisPerUnit:  10000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 1000000 * NanosPerUnit,
			SatoshisPerUnit:  20000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 2000000 * NanosPerUnit,
			SatoshisPerUnit:  40000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 3000000 * NanosPerUnit,
			SatoshisPerUnit:  80000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 4000000 * NanosPerUnit,
			SatoshisPerUnit:  160000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 5000000 * NanosPerUnit,
			SatoshisPerUnit:  320000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 6000000 * NanosPerUnit,
			SatoshisPerUnit:  640000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 7000000 * NanosPerUnit,
			SatoshisPerUnit:  1280000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 8000000 * NanosPerUnit,
			SatoshisPerUnit:  2560000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 9000000 * NanosPerUnit,
			SatoshisPerUnit:  5120000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 10000000 * NanosPerUnit,
			SatoshisPerUnit:  10240000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 11000000 * NanosPerUnit,
			SatoshisPerUnit:  20480000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 12000000 * NanosPerUnit,
			SatoshisPerUnit:  40960000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 13000000 * NanosPerUnit,
			SatoshisPerUnit:  81920000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 14000000 * NanosPerUnit,
			SatoshisPerUnit:  163840000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 15000000 * NanosPerUnit,
			SatoshisPerUnit:  327680000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 16000000 * NanosPerUnit,
			SatoshisPerUnit:  655360000,
		},
		&PurchaseSupplyIntervalStart{
			SupplyStartNanos: 17000000 * NanosPerUnit,
			// No more units can be purchased after we hit this threshold.
			SatoshisPerUnit: math.MaxUint64,
		},
	}
)

var (
	MaxNanos = CalcMaxNanos()
)

func CalcMaxNanos() uint64 {
	// Sum all of the mining intervals to make sure there is no overflow.
	totalMiningSupply := uint64(0)
	for intervalIndex, currentInterval := range MiningSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first index
			continue
		}
		prevInterval := MiningSupplyIntervals[intervalIndex-1]
		blockRewardNanos := prevInterval.BlockRewardNanos
		numBlocksInInterval := currentInterval.StartBlockHeight - prevInterval.StartBlockHeight

		numNanosMinedInInterval := blockRewardNanos * uint64(numBlocksInInterval)
		totalMiningSupply += numNanosMinedInInterval
	}

	// Sum all of the purchase intervalse to make sure there is no overflow.
	totalNanosForPurchase := uint64(0)
	for intervalIndex, currentInterval := range PurchaseSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first index
			continue
		}
		prevInterval := PurchaseSupplyIntervals[intervalIndex-1]
		nanosInTranche := currentInterval.SupplyStartNanos - prevInterval.SupplyStartNanos

		totalNanosForPurchase += nanosInTranche
	}

	return totalMiningSupply + totalNanosForPurchase
}

// CalcBlockRewardNanos computes the block reward for a given block height.
func CalcBlockRewardNanos(blockHeight uint32) uint64 {
	if blockHeight == 0 {
		return MiningSupplyIntervals[0].BlockRewardNanos
	}

	// Skip the first interval since we know we're past block height zero.
	for intervalIndex, intervalStart := range MiningSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first iteration.
			continue
		}
		if intervalStart.StartBlockHeight > blockHeight {
			// We found an interval that has a greater block height than what was
			// passed in, so the interval just before it should be the one containing
			// this block height.
			return MiningSupplyIntervals[intervalIndex-1].BlockRewardNanos
		}
	}

	// If we get here then all of the intervals had a lower block height than
	// the passed-in block height. In this case, the block reward is zero.
	return 0
}

func _computeNanosLeftInCurrentTranche(nanosCreated uint64) (
	_nanosLeftInTranche uint64, _satoshisPerUnit uint64) {

	// Iterate through the tranches until we hit a tranche with a SupplyStartNanos
	// that exceeds nanosCreated. The nanosLeftInTranche is then simply the difference
	// between this value and the nanosCreated. To get the satoshisPerUnit, we go back
	// and get the value from the previous tranche, which is the currently active one.
	for iterTrancheIndex, iterTranche := range PurchaseSupplyIntervals {
		if iterTranche.SupplyStartNanos > nanosCreated {
			// If SupplyStartNanos is the maximum value then it means we hit the tombstone
			// tranche at the end of the list. This is a bit of an edge case so in this
			// scenario we return a max value for both nanosLeft and satoshisPerUnit. This
			// makes it so that we won't print any more units after nanosCreated hits the
			// tombstone value's threshold.
			if iterTranche.SupplyStartNanos == math.MaxUint64 {
				return math.MaxUint64, math.MaxUint64
			}

			// This means the iterTranche has just exceeded the nanosCreated. Therefore
			// the nanos left in the prior tranche is simply the difference between the
			// SupplyStartNanos of the iterTranche and the nanosCreated.
			nanosLeft := iterTranche.SupplyStartNanos - nanosCreated

			// The satoshisPerUnit is the amount corresponding to the previous tranche,
			// which is the currently active one. Note we should never have an out-of-bounds
			// exception here because the block is guarded by SupplyStartNanos > nanosCreated
			// and SupplyStartNanos is 0 for the first tranche, which means we'll never get
			// here until the iterTrancheIndex is >= 1. A little tricky sorry.
			activeTranche := PurchaseSupplyIntervals[iterTrancheIndex-1]
			satoshisPerUnit := activeTranche.SatoshisPerUnit

			return nanosLeft, satoshisPerUnit
		}
	}

	// This is a bit of an edge-case but we could get here if nanosCreated
	// exceeds the tombstone value. In this case the proper thing to do is
	// to return a max value for both nanosLeftInTranche and satoshisPerUnit.
	return math.MaxUint64, math.MaxUint64
}

func GetSatoshisPerUnitExchangeRate(db *badger.DB) (uint64, uint64) {
	nanosPurchased := DbGetNanosPurchased(db)
	return _computeNanosLeftInCurrentTranche(nanosPurchased)
}

func _computeNanosNeeded(satoshisPerUnit uint64, satoshisToBurn uint64) (
	_nanosNeeded uint64, _err error) {

	// Given the maximum supply of Bitcoin, overflow should not be possible
	// in this function. Nevertheless, we check for and guard against overflow
	// in case an adversarial or unrealisting value is given for satoshisToBurn.

	// If either input exceeds the maximum value for an int64 we have an error.
	if satoshisPerUnit > math.MaxInt64 || satoshisToBurn > math.MaxInt64 {
		return 0, fmt.Errorf("_computeNanosNeeded: satoshisPerUnit %v or "+
			"satoshisToBurn %v exceed MaxInt64 %v",
			float64(satoshisPerUnit), float64(satoshisToBurn), float64(math.MaxInt64))
	}

	// This is basically just:
	// nanosNeeded = satoshisToBurn * NanosPerUnit / satoshisPerUnit
	satoshisPerUnitBigint := big.NewInt(int64(satoshisPerUnit))
	satoshisBurnedBigint := big.NewInt(int64(satoshisToBurn))
	nanosPerUnitBigint := big.NewInt(int64(NanosPerUnit))
	satoshisBurnedTimesNanosPerUnit := big.NewInt(0).Mul(
		satoshisBurnedBigint, nanosPerUnitBigint)
	nanosNeededBigint := big.NewInt(0).Div(
		satoshisBurnedTimesNanosPerUnit, satoshisPerUnitBigint)

	// If nanosNeeded exceeds the maximum value for an int64 we have an error.
	if nanosNeededBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return 0, fmt.Errorf("_computeNanosNeeded: Final value for "+
			"nanosNeeded %v exceeds maximum Int64 value %v", nanosNeededBigint, float64(math.MaxInt64))
	}

	return nanosNeededBigint.Uint64(), nil
}

func _computeSatoshisToBurn(nanosToCreate uint64, satoshisPerUnit uint64) (
	_satoshisToBurn uint64, _err error) {

	// We know because of the way we define the PurchaseSupplyIntervals that
	// satoshisToBurn will not overflow (even though the intermediate step could, which
	// is why we use bigint). Nonetheless, we check the result before assigning (because
	// only the paranoid survive).

	// If either input exceeds the maximum value for an int64 we have an error.
	if nanosToCreate > math.MaxInt64 || satoshisPerUnit > math.MaxInt64 {
		return 0, fmt.Errorf("_computeSatoshisToBurn: nanosToCreate %v or "+
			"satoshisPerUnit %v exceed MaxInt64 %v",
			float64(nanosToCreate), float64(satoshisPerUnit), float64(math.MaxInt64))
	}

	// This is basically just:
	// satoshisToBurn = nanosToCreate * satoshisPerUnit / NanosPerUnit
	nanosToCreateBigint := big.NewInt(int64(nanosToCreate))
	satoshisPerUnitBigint := big.NewInt(int64(satoshisPerUnit))
	nanosToCreateTimesSatoshisPerUnit := big.NewInt(0).Mul(
		nanosToCreateBigint, satoshisPerUnitBigint)
	nanosPerUnitBigint := big.NewInt(int64(NanosPerUnit))
	satoshisToBurnBigint := big.NewInt(0).Div(
		nanosToCreateTimesSatoshisPerUnit, nanosPerUnitBigint)

	// If satoshisToBurn exceeds the maximum value for an int64 we have an error.
	if satoshisToBurnBigint.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return 0, fmt.Errorf("_computeSatoshisToBurn: Final value for "+
			"satoshisToBurn %v exceeds maximum Int64 value %v",
			satoshisToBurnBigint, float64(math.MaxInt64))
	}

	return satoshisToBurnBigint.Uint64(), nil
}

func CalcNanosToCreate(startNanos uint64, satoshisToBurn uint64) (
	_nanosToCreate uint64, _err error) {

	// Each iteration is guaranteed to either return or result in an increase
	// in currentNanos. The latter, when incremented enough times, results in
	// the triggering of a return. So we should be safe against an infinite
	// looping here.
	currentNanos := startNanos
	for {
		nanosLeftInTranche, satoshisPerUnit :=
			_computeNanosLeftInCurrentTranche(currentNanos)

		// If we hit the tombstone value then we cannot create any more units.
		// Just return here with what we've managed to create thus far. Could
		// be zero and that's OK.
		if nanosLeftInTranche == math.MaxUint64 {
			nanosToCreate := currentNanos - startNanos
			return nanosToCreate, nil
		}

		// Assuming we have not hit the maximum number of nanos that can be created
		// figure out the maximum amount of Bitcoin we could burn if we consumed
		// everything in this tranche.
		maxSatoshiToBurnInTranche, err := _computeSatoshisToBurn(nanosLeftInTranche, satoshisPerUnit)
		if err != nil {
			return 0, errors.Wrapf(err, "CalcNanosToCreate: Problem computing "+
				"maxSatoshiToBurnInTranche: ")
		}

		// If the satoshiToBurn can be satisfied by the current tranche then we are
		// finished.
		if maxSatoshiToBurnInTranche >= satoshisToBurn {
			nanosNeededd, err := _computeNanosNeeded(satoshisPerUnit, satoshisToBurn)
			if err != nil {
				return 0, errors.Wrapf(err, "CalcNanosToCreate: Problem computing "+
					"nanosNeeded in final tranche: ")
			}

			// No chance for overflow here because the sum of all the nanos across
			// all the tranches won't overflow. Nevertheless, check because we are
			// very paranoid.
			if currentNanos > math.MaxUint64-nanosNeededd {
				return 0, fmt.Errorf("CalcNanosToCreate: Summing currentNanos %d and "+
					"nanosNeeded %d would cause overflow of max Uint64 %s; this should "+
					"never happen", currentNanos, nanosNeededd,
					strconv.FormatUint(math.MaxUint64, 10))
			}
			currentNanos += nanosNeededd
			return currentNanos - startNanos, nil
		}

		// At this point we are confident that maxSatoshiToBurnInTranche is < satoshisToBurn
		// and that consuming the tranche is not sufficient to satisfy satoshisToBurn yet.
		// Update satoshisToBurn and currentNanos and continue to the next iteration. Note
		// there should be no chance of overflowing currentNanos but we check it anyway
		// because we are very paranoid.
		satoshisToBurn -= maxSatoshiToBurnInTranche
		if currentNanos > math.MaxUint64-nanosLeftInTranche {
			return 0, fmt.Errorf("CalcNanosToCreate: Summing currentNanos %d and "+
				"nanosLeftInTranche %d would cause overflow of max Uint64 %s; this should "+
				"never happen", currentNanos, nanosLeftInTranche,
				strconv.FormatUint(math.MaxUint64, 10))
		}
		currentNanos += nanosLeftInTranche
	}
}
