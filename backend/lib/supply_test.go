package lib

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	satoshisPerBitcoin = 100000000
)

func TestTotalSupply(t *testing.T) {
	require := require.New(t)

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
	require.Equal(509832*NanosPerUnit, totalMiningSupply)

	// Sum all of the purchase intervalse to make sure there is no overflow.
	totalNanosForPurchase := uint64(0)
	totalSatoshisBurned := uint64(0)
	for intervalIndex, currentInterval := range PurchaseSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first index
			continue
		}
		prevInterval := PurchaseSupplyIntervals[intervalIndex-1]
		nanosInTranche := currentInterval.SupplyStartNanos - prevInterval.SupplyStartNanos
		satoshisPerUnit := prevInterval.SatoshisPerUnit
		satoshisToBurn, err := _computeSatoshisToBurn(nanosInTranche, satoshisPerUnit)
		require.NoErrorf(err, "Error with overflow at purchase index %d", intervalIndex)

		if nanosInTranche > math.MaxUint64-totalNanosForPurchase {
			require.Truef(false, "Overflow: nanosInTranche %d + totalNanosForPurchase "+
				"%d > MaxUint64 %d", nanosInTranche, totalNanosForPurchase,
				strconv.FormatUint(math.MaxUint64, 10))
		}
		totalNanosForPurchase += nanosInTranche
		if satoshisToBurn > math.MaxUint64-totalSatoshisBurned {
			require.Truef(false, "Overflow: satoshisToBurn %d + totalSatoshisBurned "+
				"%d > MaxUint64 %d", satoshisToBurn, totalSatoshisBurned,
				strconv.FormatUint(math.MaxUint64, 10))
		}
		totalSatoshisBurned += satoshisToBurn
	}
	require.Equal(17000000*NanosPerUnit, totalNanosForPurchase)
	require.Equal(int64(13107100*satoshisPerBitcoin), int64(totalSatoshisBurned))
	require.Equal(int64(totalMiningSupply+totalNanosForPurchase), int64(CalcMaxNanos()))
}

func TestCalcBlockReward(t *testing.T) {
	require := require.New(t)

	require.Equal(2*NanosPerUnit, CalcBlockRewardNanos(0))
	require.Equal(2*NanosPerUnit, CalcBlockRewardNanos(1))
	require.Equal(2*NanosPerUnit, CalcBlockRewardNanos(1*BlocksPerYear-1))
	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(1*BlocksPerYear))
	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(1*BlocksPerYear+1))
	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(3*BlocksPerYear-1))
	require.Equal(NanosPerUnit/2, CalcBlockRewardNanos(3*BlocksPerYear))
	require.Equal(NanosPerUnit/2, CalcBlockRewardNanos(3*BlocksPerYear+1))
	require.Equal(NanosPerUnit/2, CalcBlockRewardNanos(7*BlocksPerYear-1))
	require.Equal(NanosPerUnit/4, CalcBlockRewardNanos(7*BlocksPerYear))
	require.Equal(NanosPerUnit/4, CalcBlockRewardNanos(7*BlocksPerYear+1))
	require.Equal(NanosPerUnit/4, CalcBlockRewardNanos(15*BlocksPerYear-1))
	require.Equal(NanosPerUnit/10, CalcBlockRewardNanos(15*BlocksPerYear))
	require.Equal(NanosPerUnit/10, CalcBlockRewardNanos(15*BlocksPerYear+1))
	require.Equal(NanosPerUnit/10, CalcBlockRewardNanos(32*BlocksPerYear-1))
	require.Equal(uint64(0), CalcBlockRewardNanos(32*BlocksPerYear))
	require.Equal(uint64(0), CalcBlockRewardNanos(32*BlocksPerYear+1))
	require.Equal(uint64(0), CalcBlockRewardNanos(35*BlocksPerYear+1))
	require.Equal(uint64(0), CalcBlockRewardNanos(math.MaxUint32))
}

func TestCalcNanosToCreate(t *testing.T) {
	require := require.New(t)

	{
		// Zero satoshi means zero nanos
		nanosToCreate, err := CalcNanosToCreate(0, 0)
		require.NoError(err)
		require.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshi means zero nanos: first tranche
		nanosToCreate, err := CalcNanosToCreate(10, 0)
		require.NoError(err)
		require.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshi means zero nanos: second tranche
		nanosToCreate, err := CalcNanosToCreate(1000001*NanosPerUnit, 0)
		require.NoError(err)
		require.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshi means zero nanos: after the end of the PurchaseSupplyIntervals
		nanosToCreate, err := CalcNanosToCreate(18000001*NanosPerUnit, 0)
		require.NoError(err)
		require.Equal(uint64(0), nanosToCreate)
	}
	{
		// No nanos should be created after the end of the PurchaseSupplyInterval
		// even if the number of satoshis is non-zero.
		nanosToCreate, err := CalcNanosToCreate(18000001*NanosPerUnit, satoshisPerBitcoin+1)
		require.NoError(err)
		require.Equal(uint64(0), nanosToCreate)
	}
	{
		// The first purchase should work.
		nanosToCreate, err := CalcNanosToCreate(0*NanosPerUnit, satoshisPerBitcoin+1)
		require.NoError(err)
		require.Equal(int64(10000000100000), int64(nanosToCreate))
	}
	{
		// The first purchase should work even if it overflows the first tranche.
		// In this case, the purchase should result in a blended price between the first
		// and second tranche.
		nanosToCreate, err := CalcNanosToCreate(0*NanosPerUnit, 200*satoshisPerBitcoin+1)
		require.NoError(err)
		require.Equal(int64(1500000000050000), int64(nanosToCreate))
	}
	{
		// Making a purchase part-way through the first tranche should work.
		nanosToCreate, err := CalcNanosToCreate(200001*NanosPerUnit, satoshisPerBitcoin+1)
		require.NoError(err)
		require.Equal(int64(10000000100000), int64(nanosToCreate))
	}
	{
		// A purchase part-way through the first tranche should work even if it overflows
		// the first tranche.
		// In this case, the purchase should result in a blended price between the first
		// and second tranche.
		nanosToCreate, err := CalcNanosToCreate(200001*NanosPerUnit, 200*satoshisPerBitcoin+1)
		require.NoError(err)
		require.Equal(int64(1399999500050000), int64(nanosToCreate))
	}
	{
		// A purchase part-way through a middle tranche should work.
		nanosToCreate, err := CalcNanosToCreate(6123456123456789, 5712345678)
		require.NoError(err)
		require.Equal(int64(8925540121875), int64(nanosToCreate))
	}

	{
		// A purchase to the end of a threshold should work
		startVal := uint64(6123456123456789)
		nanosToCreate, err := CalcNanosToCreate(startVal, 560988080987)
		require.NoError(err)
		// Be careful: Your calculator will lose precision when you try to calculate this
		// to check it if you let it do floating point at any step.
		require.Equal(int64(6999999999998976), int64(nanosToCreate)+int64(startVal))
	}
	{
		// A purchase just barely passing a threshold should work. This is tricky. When
		// passing a threshold, the function effectively "rounds up" giving you a tiny
		// discount. In this example, this happens as follows:
		// - The max BTC to buy up the tranche is computed to be (satoshiToBurn - 1)
		// - So it gives the purchaser the entire tranche, even though
		//   ((satoshiToBurn-1) * NanosPerUnit / satoshisPerUnit) equals slightly less
		//   than the nanosLeftInTranche. The difference is effectively given to the
		//   purchaser for free since it would take less than one satoshi to clean out
		//   the rest of the tranche anyway.
		// - Then there is 1 satoshiToBurn left and that buys a number of nanos at the
		//   new exchange rate for the next tranche.
		startVal := uint64(6123456123456789)
		nanosToCreate, err := CalcNanosToCreate(startVal, 560988080988)
		require.NoError(err)
		require.Equal(int64(7000000000000781), int64(startVal)+int64(nanosToCreate))
	}

	{
		// Try a weird situation where there is less than one satoshi left worth of nanos
		// at the end of a tranche and the purchaser tries to buy zero satoshis. This should
		// result in zero nanos being created.
		startVal := uint64(7000000000000000 - 99)
		nanosToCreate, err := CalcNanosToCreate(startVal, 0)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a weird situation where there is less than one satoshi left worth of nanos
		// at the end of a tranche and the purchaser tries to buy one satoshi worth of nanos.
		// This should result in the purchaser clearing out the previous tranche for free and
		// then getting the single satoshi converted at the price for the next tranche.
		startVal := uint64(7000000000000000 - 99)
		nanosToCreate, err := CalcNanosToCreate(startVal, 1)
		require.NoError(err)
		require.Equal(int64(99+1*1000000000/1280000), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche and buys just before
		// the end (i.e. doesn't completely clear out the final tranche).
		startVal := uint64(16000000123456789)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		satoshisToCleanOutTranche := uint64(655359919091358)
		nanosToCreate, err := CalcNanosToCreate(startVal, satoshisToCleanOutTranche)
		require.NoError(err)
		require.Equal(int64(16999999999999998), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and zero satoshis are burned.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate, err := CalcNanosToCreate(startVal, 0)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 1 satoshi is burned.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate, err := CalcNanosToCreate(startVal, 1)
		require.NoError(err)
		require.Equal(int64(1), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 2 satoshi is burned.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate, err := CalcNanosToCreate(startVal, 2)
		require.NoError(err)
		require.Equal(int64(2), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 3 satoshi is burned. In this case we should not cross the threshold.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate, err := CalcNanosToCreate(startVal, 3)
		require.NoError(err)
		require.Equal(int64(2), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche and buys just *beyond*
		// the end (i.e. fully completes the last tranche).
		startVal := uint64(16000000123456789)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		satoshisToCleanOutTranche := uint64(655359919091359)
		nanosToCreate, err := CalcNanosToCreate(startVal, satoshisToCleanOutTranche)
		require.NoError(err)
		require.Equal(int64(17000000000000000), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche and buys way *beyond*
		// the end (i.e. fully completes the last tranche).
		startVal := uint64(16000000123456789)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		satoshisToCleanOutTranche := uint64(665359919091359)
		nanosToCreate, err := CalcNanosToCreate(startVal, satoshisToCleanOutTranche)
		require.NoError(err)
		require.Equal(int64(17000000000000000), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts at the end and buys zero. Should result
		// in no nanos being created.
		startVal := uint64(17000000000000000)
		nanosToCreate, err := CalcNanosToCreate(startVal, 0)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts at the end and burns one satoshi. Should result
		// in no nanos being created.
		startVal := uint64(17000000000000000)
		nanosToCreate, err := CalcNanosToCreate(startVal, 1)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts beyond the end and burns one satoshi.
		// Should never happen but should result in no nanos being created nevertheless.
		startVal := uint64(17000000000000001)
		nanosToCreate, err := CalcNanosToCreate(startVal, 1)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Trying to burn a huge amount of Bitcoin should still result in zero nanos
		// being printed.
		startVal := uint64(17000000000000000 - 99)
		nanosToCreate, err := CalcNanosToCreate(startVal, 21000000*satoshisPerBitcoin)
		require.NoError(err)
		require.Equal(int64(99), int64(nanosToCreate))
	}
	{
		// Trying to burn a huge amount of Bitcoin should still result in zero nanos
		// being printed.
		startVal := uint64(17000000000000000)
		nanosToCreate, err := CalcNanosToCreate(startVal, 21000000*satoshisPerBitcoin)
		require.NoError(err)
		require.Equal(int64(0), int64(nanosToCreate))
	}
}
