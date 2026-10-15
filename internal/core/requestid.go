package core

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// crockford 是 ULID 使用的 Crockford Base32 字符表（去除了易混淆的 I/L/O/U）。
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// requestIDRandMu 保护随机数读取，避免在极端并发下重复取数产生抖动。
var requestIDRandMu sync.Mutex

// NewRequestID 生成一个 26 字符的请求标识（ULID 形态：48 位毫秒时间戳 + 80 位随机数）。
//
// 之所以自研而不引入第三方库：
//   - 需求要求离线交付与最小依赖；
//   - 该标识只需「单调递增前缀 + 足够随机 + 可排序」，ULID 形态即可满足，
//     并且与设计文档中给出的示例（26 位 Crockford Base32）保持一致。
func NewRequestID(now time.Time) string {
	var raw [16]byte

	// 前 6 字节为毫秒时间戳（大端），保证同一进程内标识按时间有序。
	ms := uint64(now.UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)

	// 后 10 字节为加密安全随机数；读取失败时退化为时间派生值，保证函数不返回空串。
	requestIDRandMu.Lock()
	_, err := rand.Read(raw[6:])
	requestIDRandMu.Unlock()
	if err != nil {
		binary.BigEndian.PutUint64(raw[8:], uint64(now.UnixNano()))
	}

	return encodeCrockford(raw)
}

// encodeCrockford 把 16 字节编码为 26 个 Crockford Base32 字符。
//
// 编码方式与 ULID 一致：整体视为 128 位整数，取高 130 位中的前 26 组 5 位。
func encodeCrockford(raw [16]byte) string {
	// ulid 规范：26 个字符共 130 位，最高 2 位补零，因此首字符仅取低 3 位。
	out := make([]byte, 26)

	// 直接按位取值，避免大整数运算带来的额外分配。
	for i := 25; i >= 0; i-- {
		bitPos := uint(i * 5)
		value := byte(0)
		for b := 0; b < 5; b++ {
			pos := bitPos + uint(b)
			if pos >= 128 {
				continue // 超出 128 位的高位补零
			}
			// 从高位到低位读取：bit 127 对应 raw[0] 的最高位。
			byteIndex := 15 - int(pos/8)
			bitIndex := uint(pos % 8)
			bit := (raw[byteIndex] >> bitIndex) & 0x01
			value |= bit << uint(4-b)
		}
		out[i] = crockford[value%32]
	}
	return string(out)
}
