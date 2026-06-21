package notifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeUsedByType(t *testing.T) {
	assert.Equal(t, int64(100), ComputeUsedByType("up", 100, 200))
	assert.Equal(t, int64(200), ComputeUsedByType("down", 100, 200))
	assert.Equal(t, int64(300), ComputeUsedByType("sum", 100, 200))
	assert.Equal(t, int64(100), ComputeUsedByType("min", 100, 200))
	assert.Equal(t, int64(200), ComputeUsedByType("max", 100, 200))
	assert.Equal(t, int64(200), ComputeUsedByType("unknown", 100, 200))
}
