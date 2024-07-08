package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

type OpCode uint8

const (
	OpFrag  OpCode = 0x0
	OpText  OpCode = 0x1
	OpBin   OpCode = 0x2
	OpClose OpCode = 0x8
)

type Frame struct {
	// Raw unmasked payload bytes.
	Pay []byte

	// Opcode from header.
	Op OpCode

	// Extension bits from header.
	//
	//	7 6 5 4 3 2 1 0 # bits order: most -> least significant
	//	- - - - - 1 2 3 # order of extension bits
	Ext uint8

	// Final (last) frame in message.
	Fin bool
}

type Decoder struct {
	// Size in bytes. If frame payload exceeds this limit, then
	// decoder will return FrameDecodeError upon reading and decoding
	// header of such a frame. In that case the rest of the data inside
	// the given reader will be left untouched.
	MaxFramePayloadSize uint64

	// If true decoder expects frame to be masked.
	Mask bool
}

func (d *Decoder) Decode(r io.Reader) (Frame, error) {
	// fixed buffer for reading frame header
	var buf [12]byte

	n, err := r.Read(buf[:2])
	if err != nil {
		return Frame{}, err
	}
	if n != 2 {
		return Frame{}, &FrameDecodeError{}
	}

	fin := (buf[0] >> 7) == 1
	ext := (buf[0] >> 4) & 0x7
	op := OpCode(buf[0] & 0xf)
	useMask := (buf[1] >> 7) == 1
	sizeBits := buf[1] & 0x7f

	fmt.Printf("fin: %v\n", fin)
	fmt.Printf("ext bits: %03b\n", ext)
	fmt.Printf("op: 0x%x\n", op)
	fmt.Printf("use mask: %v\n", useMask)
	fmt.Printf("size bits: %b\n", sizeBits)

	// TODO: check extension bits
	// TODO: check opcode value

	if useMask != d.Mask {
		return Frame{}, &FrameDecodeError{}
	}

	size := uint64(sizeBits)
	pos := 0
	headerExtraSize := calcHeaderExtraSize(useMask, sizeBits)
	if headerExtraSize > 0 {
		n, err := r.Read(buf[:headerExtraSize])
		if err != nil {
			return Frame{}, err
		}
		if n != headerExtraSize {
			return Frame{}, &FrameDecodeError{}
		}

		if sizeBits == 126 {
			size = uint64(binary.BigEndian.Uint16(buf[:2]))
			pos = 2
		} else if sizeBits == 127 {
			size = binary.BigEndian.Uint64(buf[:8])
			pos = 8
		}
	}

	fmt.Printf("size: %d\n", size)

	if size > d.MaxFramePayloadSize {
		return Frame{}, &FrameDecodeError{}
	}

	var mask [4]byte
	if d.Mask {
		copy(mask[:], buf[pos:headerExtraSize])
		fmt.Printf("mask: 0x%04x\n", mask)
	}

	var payload []byte
	if size != 0 {
		payload = make([]byte, size)
		_, err := io.ReadFull(r, payload)
		if err != nil {
			return Frame{}, err
		}
	}

	if d.Mask {
		// unmask payload
		for i := 0; i < len(payload); i++ {
			payload[i] ^= mask[i&0b11]
		}
	}

	fmt.Printf("payload: %s\n", payload)

	return Frame{
		Pay: payload,
		Op:  op,
		Ext: ext,
		Fin: fin,
	}, nil
}

func calcHeaderExtraSize(useMask bool, sizeBits uint8) int {
	size := 0
	if useMask {
		size += 4
	}

	if sizeBits == 126 {
		size += 2
	} else if sizeBits == 127 {
		size += 8
	}

	return size
}

type FrameDecodeError struct {
}

func (e *FrameDecodeError) Error() string {
	return ""
}

type MaskSource interface {
	GenMask() [4]byte
}

type Encoder struct {
	// Stream for writing encoded frames.
	Sink io.Writer

	// If this field is not nil, then it will be used to mask
	// the frame during encoding.
	Mask MaskSource
}

func (e *Encoder) Encode(frame Frame) error {
	// fixed buffer for encoding frame header
	var buf [14]byte

	if len(frame.Pay) == 0 {
		return nil
	}

	return e.encodePayload(frame.Pay)
}

func (e *Encoder) encodePayload(p []byte) error {
	if e.Mask == nil {
		_, err := e.Sink.Write(p)
		return err
	}

	// mask and write payload using separate fixed buffer
	mask := e.Mask.GenMask()

	const bufSize = 1 << 14
	var buf [bufSize]byte

	// position inside payload slice
	var pos int

	for j := 0; j < (len(p) >> 14); j += 1 {
		// outer loop cycles through full buffer chunks

		for i := 0; i < bufSize; i += 1 {
			// place masked byte into buffer
			buf[i] = p[pos] ^ mask[i&0b11]
			pos += 1
		}

		_, err := e.Sink.Write(buf[:])
		if err != nil {
			return err
		}
	}

	if pos >= len(p) {
		return nil
	}

	// write remaining portion of payload
	n := len(p) & (bufSize - 1)
	for i := 0; i < n; i += 1 {
		buf[i] = p[pos] ^ mask[i&0b11]
		pos += 1
	}

	_, err := e.Sink.Write(buf[:n])
	return err
}
