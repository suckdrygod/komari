package notifier

import (
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGetClientTrafficInRangeAvoidsOverlappingRawAndLongTermRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-overlap"
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sharedSlot := start.Add(15 * time.Minute)

	assert.NoError(t, db.Table("records_long_term").Create(&models.Record{
		Client:      clientUUID,
		Time:        models.FromTime(sharedSlot),
		TrafficUp:   100,
		TrafficDown: 200,
	}).Error)

	rawRecords := []models.Record{
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(1 * time.Minute)), TrafficUp: 40, TrafficDown: 80},
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(5 * time.Minute)), TrafficUp: 60, TrafficDown: 120},
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(16 * time.Minute)), TrafficUp: 30, TrafficDown: 50},
	}
	for _, record := range rawRecords {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, sharedSlot.Add(30*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(380), used)
}

func TestGetClientTrafficInRangeNormalizesLongTermSlotForOverlap(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-overlap-normalized"
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sharedSlot := start.Add(15 * time.Minute)

	assert.NoError(t, db.Table("records_long_term").Create(&models.Record{
		Client:      clientUUID,
		Time:        models.FromTime(sharedSlot.Add(8 * time.Minute)),
		TrafficUp:   100,
		TrafficDown: 200,
	}).Error)

	rawRecords := []models.Record{
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(1 * time.Minute)), TrafficUp: 40, TrafficDown: 80},
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(5 * time.Minute)), TrafficUp: 60, TrafficDown: 120},
		{Client: clientUUID, Time: models.FromTime(sharedSlot.Add(16 * time.Minute)), TrafficUp: 30, TrafficDown: 50},
	}
	for _, record := range rawRecords {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, sharedSlot.Add(30*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(380), used)
}

func TestGetClientTrafficInRangeSumsPersistedDeltasAcrossCounterReset(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-reset"
	start := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 100, NetTotalDown: 200, TrafficUp: 0, TrafficDown: 0},
		{Client: clientUUID, Time: models.FromTime(start.Add(5 * time.Minute)), NetTotalUp: 150, NetTotalDown: 260, TrafficUp: 50, TrafficDown: 60},
		{Client: clientUUID, Time: models.FromTime(start.Add(10 * time.Minute)), NetTotalUp: 10, NetTotalDown: 30, TrafficUp: 10, TrafficDown: 30},
		{Client: clientUUID, Time: models.FromTime(start.Add(15 * time.Minute)), NetTotalUp: 25, NetTotalDown: 40, TrafficUp: 15, TrafficDown: 10},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(20*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(175), used)
}

func TestGetLatestClientTrafficResetFindsMostRecentCounterDrop(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-reset-date"
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start), NetTotalUp: 100, NetTotalDown: 200},
		{Client: clientUUID, Time: models.FromTime(start.Add(time.Hour)), NetTotalUp: 130, NetTotalDown: 260},
		{Client: clientUUID, Time: models.FromTime(start.AddDate(0, 1, 0)), NetTotalUp: 5, NetTotalDown: 8},
		{Client: clientUUID, Time: models.FromTime(start.AddDate(0, 1, 0).Add(time.Hour)), NetTotalUp: 20, NetTotalDown: 30},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	resetAt, found, err := getLatestClientTrafficResetWithDB(db, clientUUID, start.Add(-time.Hour), start.AddDate(0, 1, 1))
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, start.AddDate(0, 1, 0), resetAt)
}

func TestGetClientTrafficInRangeFallsBackForPersistedZeroDeltas(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-zero-deltas"
	start := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(-5 * time.Minute)), NetTotalUp: 100, NetTotalDown: 200},
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 130, NetTotalDown: 250},
		{Client: clientUUID, Time: models.FromTime(start.Add(5 * time.Minute)), NetTotalUp: 160, NetTotalDown: 310},
		{Client: clientUUID, Time: models.FromTime(start.Add(10 * time.Minute)), NetTotalUp: 10, NetTotalDown: 30},
		{Client: clientUUID, Time: models.FromTime(start.Add(15 * time.Minute)), NetTotalUp: 25, NetTotalDown: 40},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(20*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(195), used)
}

func TestGetClientTrafficInRangeIgnoresZeroDeltaCounterRollbacks(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-interleaved-counters"
	start := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(-1 * time.Minute)), NetTotalUp: 1000, NetTotalDown: 2000},
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 1030, NetTotalDown: 2050},
		{Client: clientUUID, Time: models.FromTime(start.Add(1 * time.Minute)), NetTotalUp: 650, NetTotalDown: 900},
		{Client: clientUUID, Time: models.FromTime(start.Add(2 * time.Minute)), NetTotalUp: 1040, NetTotalDown: 2060},
		{Client: clientUUID, Time: models.FromTime(start.Add(3 * time.Minute)), NetTotalUp: 660, NetTotalDown: 910},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(5*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(100), used)
}

func TestGetClientTrafficInRangeCapsStoredDeltasDuringCounterRollback(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-stored-delta-spike"
	start := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(-1 * time.Minute)), NetTotalUp: 1000, NetTotalDown: 2000},
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 1030, NetTotalDown: 2050, TrafficUp: 30, TrafficDown: 50},
		{Client: clientUUID, Time: models.FromTime(start.Add(1 * time.Minute)), NetTotalUp: 650, NetTotalDown: 900},
		{Client: clientUUID, Time: models.FromTime(start.Add(2 * time.Minute)), NetTotalUp: 1040, NetTotalDown: 2060, TrafficUp: 390, TrafficDown: 1160},
		{Client: clientUUID, Time: models.FromTime(start.Add(3 * time.Minute)), NetTotalUp: 660, NetTotalDown: 910},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(5*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(100), used)
}

func TestGetClientTrafficInRangeKeepsStoredResetDeltas(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-legitimate-reset"
	start := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(-1 * time.Minute)), NetTotalUp: 1000, NetTotalDown: 2000},
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 20, NetTotalDown: 30, TrafficUp: 20, TrafficDown: 30},
		{Client: clientUUID, Time: models.FromTime(start.Add(1 * time.Minute)), NetTotalUp: 35, NetTotalDown: 55, TrafficUp: 15, TrafficDown: 25},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(5*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(90), used)
}

func TestGetClientTrafficInRangeCountsOnlyAboveRollbackHighWater(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-returns-to-high-water"
	start := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	records := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start.Add(-1 * time.Minute)), NetTotalUp: 1000, NetTotalDown: 2000},
		{Client: clientUUID, Time: models.FromTime(start.Add(0 * time.Minute)), NetTotalUp: 650, NetTotalDown: 900},
		{Client: clientUUID, Time: models.FromTime(start.Add(1 * time.Minute)), NetTotalUp: 700, NetTotalDown: 950},
		{Client: clientUUID, Time: models.FromTime(start.Add(2 * time.Minute)), NetTotalUp: 1030, NetTotalDown: 2040},
	}
	for _, record := range records {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(5*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(170), used)
}

func TestGetClientTrafficInRangeFallsBackForLongTermZeroDeltas(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-long-term-zero-deltas"
	start := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	assert.NoError(t, db.Create(&models.Record{
		Client:       clientUUID,
		Time:         models.FromTime(start.Add(-15 * time.Minute)),
		NetTotalUp:   100,
		NetTotalDown: 200,
	}).Error)

	longTermRecords := []models.Record{
		{Client: clientUUID, Time: models.FromTime(start), NetTotalUp: 140, NetTotalDown: 260},
		{Client: clientUUID, Time: models.FromTime(start.Add(15 * time.Minute)), NetTotalUp: 180, NetTotalDown: 330},
	}
	for _, record := range longTermRecords {
		assert.NoError(t, db.Table("records_long_term").Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, start.Add(30*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(210), used)
}

func TestGetClientTrafficInRangePrefersRawSlotOverZeroLongTermSlot(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&models.Record{}))
	assert.NoError(t, db.Table("records_long_term").AutoMigrate(&models.Record{}))

	clientUUID := "client-zero-long-term-with-raw-reset"
	start := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	slot := start.Add(15 * time.Minute)
	assert.NoError(t, db.Create(&models.Record{
		Client:       clientUUID,
		Time:         models.FromTime(start.Add(-5 * time.Minute)),
		NetTotalUp:   100,
		NetTotalDown: 200,
	}).Error)

	assert.NoError(t, db.Table("records_long_term").Create(&models.Record{
		Client:       clientUUID,
		Time:         models.FromTime(slot),
		NetTotalUp:   15,
		NetTotalDown: 25,
		TrafficUp:    0,
		TrafficDown:  0,
	}).Error)

	rawRecords := []models.Record{
		{Client: clientUUID, Time: models.FromTime(slot.Add(1 * time.Minute)), NetTotalUp: 130, NetTotalDown: 240},
		{Client: clientUUID, Time: models.FromTime(slot.Add(5 * time.Minute)), NetTotalUp: 10, NetTotalDown: 20},
		{Client: clientUUID, Time: models.FromTime(slot.Add(10 * time.Minute)), NetTotalUp: 15, NetTotalDown: 25},
	}
	for _, record := range rawRecords {
		assert.NoError(t, db.Create(&record).Error)
	}

	used, err := getClientTrafficInRangeWithDB(db, clientUUID, "sum", start, slot.Add(15*time.Minute))
	assert.NoError(t, err)
	assert.Equal(t, int64(80), used)
}

func TestFormatCompactTrafficCard(t *testing.T) {
	message := FormatCompactTrafficCard("VPS <01>", "上周", TrafficTotals{
		Up:   12 * 1024 * 1024,
		Down: 608 * 1024 * 1024,
	})

	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n🔼 上传: 12.00 MB\n🔽 下载: 608.00 MB\n📊 上周: <b>620.00 MB</b>", message)
}
