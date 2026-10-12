<?php

declare(strict_types=1);

namespace Stokehold;

/**
 * A frame ready to send: a message type, a request id, and a payload.
 *
 * The write side of the codec. It only ever produces bytes; decoding is
 * [`Header::decode`] plus the payload reader in [`Worker`].
 */
final class Frame
{
    public function __construct(
        public readonly int $messageType,
        public readonly int $requestId,
        public readonly string $payload = '',
        public readonly int $flags = 0,
    ) {
    }

    /**
     * Serialize to header + payload.
     *
     * `pack('VCCvVV', …)` lays the six fields out little-endian at the right
     * offsets: 4 + 1 + 1 + 2 + 4 + 4 = 16 bytes.
     *
     * `$checksum` is passed in rather than remembered here, because the decision belongs to the
     * [`Worker`] that made the handshake agreement — a `Frame` is built by application-adjacent
     * code that has no business choosing a policy, and a process-wide switch would be state
     * that outlives the worker which set it.
     *
     * With the checksum off the field is written as zero and `FLAG_NO_CHECKSUM` is raised, which
     * is what makes the zero mean "not a checksum" rather than "the checksum of an empty
     * payload" — see [`Header::FLAG_NO_CHECKSUM`]. The saving is the whole point: `crc32c` walks
     * every payload byte, and a response body is the largest payload the protocol carries.
     */
    public function encode(bool $checksum = true): string
    {
        return pack(
            'VCCvVV',
            strlen($this->payload),
            Header::PROTOCOL_VERSION,
            $this->messageType,
            $checksum ? $this->flags : ($this->flags | Header::FLAG_NO_CHECKSUM),
            $this->requestId,
            $checksum ? self::crc32c($this->payload) : 0,
        ) . $this->payload;
    }

    /**
     * CRC-32C (Castagnoli) as the 32-bit value the header carries.
     *
     * `hash('crc32c', …)` returns the digest big-endian, so the raw digest is
     * reversed to get the little-endian integer. Deliberately not
     * `hexdec(hash(...))` followed by `pack('V', …)`: on a 32-bit PHP build
     * `hexdec` returns a *float* once the top bit is set, which silently
     * corrupts the checksum. `strrev` is exact everywhere.
     *
     * The check value is the standard one, and it is what Rust's `crc32c`
     * computes too: `crc32c("123456789") === 0xE3069283`.
     */
    public static function crc32c(string $data): int
    {
        /** @var int $value */
        $value = unpack('V', strrev(hash('crc32c', $data, true)))[1];

        return $value;
    }
}
