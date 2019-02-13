package doubleratchet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testRatchetCipherKeyBytes = []byte{
		0xfb, 0x6b, 0x75, 0xb1, 0x86, 0x43, 0x61, 0x38,
		0xfc, 0xb9, 0x7a, 0xdd, 0xdb, 0x39, 0xf6, 0x37,
		0xa5, 0x6b, 0x86, 0xdd, 0x90, 0x5c, 0xcb, 0x65,
		0x76, 0x61, 0xca, 0xf4, 0xbb, 0x00, 0x19, 0xc4,
	}
	testRatchetCipherPlainTextBytes = []byte{
		0x14, 0xd6, 0xbe, 0x44, 0x7f, 0x8c, 0xcd, 0x9c,
		0x61, 0xda, 0xf2, 0x60, 0x0c, 0x1c, 0xb1, 0x00,
		0xf3, 0x0a, 0x8e, 0x30, 0x0d, 0xbb, 0xf0, 0xba,
		0x71, 0x06, 0xe5, 0xf1, 0x9b, 0x26, 0xe6, 0x1c,
		0x09, 0x77, 0x4c, 0xb9, 0x62, 0xaf, 0xb0, 0x61,
		0x62, 0x05, 0xd9, 0x50, 0xad, 0x5a, 0x30, 0xf4,
		0x37, 0x09, 0xfd, 0x5e, 0xd1, 0xe5, 0xa1, 0xf1,
		0xe9, 0xf8, 0xad, 0x0d, 0x78, 0xab, 0xcd, 0xb4,
		0x93, 0x26, 0x7a, 0xf0, 0xa7, 0x3f, 0x91, 0xfa,
		0x8f, 0xff, 0x30, 0x9e, 0x52, 0xe2, 0x97, 0x53,
		0x7f, 0x90, 0x90, 0x84, 0xb7, 0x4c, 0x88, 0x13,
		0xb1, 0x48, 0x16, 0xc8, 0xe0, 0xb4, 0x28, 0x74,
		0xac, 0x9b, 0x16, 0xb3, 0x31, 0x3a, 0x1e, 0x10,
		0xb2, 0x25, 0x82, 0x38, 0x23, 0x38, 0xcd, 0x65,
		0xe7, 0xb0, 0x64, 0x6e, 0x44, 0x2a, 0xdd, 0x31,
		0x54, 0x2d, 0x09, 0x26, 0xeb, 0xb6, 0x8f, 0xef,
		0xec, 0xa3, 0x1e, 0x2b, 0x50, 0x4d, 0x8d, 0xac,
		0x01, 0x99, 0x0f, 0x16, 0x12, 0x1e, 0xf8, 0xf1,
		0xd0, 0x01, 0xe6, 0xbd, 0x4f, 0x93, 0xe9, 0x7e,
		0xdc, 0xf3, 0x19, 0x80, 0xfe, 0xf0, 0x77, 0x88,
		0x00, 0x24, 0xb3, 0x85, 0x90, 0x1c, 0x91, 0x75,
		0xf0, 0x49, 0x63, 0xc8, 0xd8, 0x01, 0xc8, 0x5c,
		0x84, 0xa0, 0xdb, 0x5a, 0x20, 0xbf, 0xf3, 0xb3,
		0x37, 0xf7, 0x6a, 0x70, 0x92, 0x34, 0xae, 0x76,
		0x8c, 0xf7, 0x16, 0x82, 0x99, 0x82, 0x7e, 0x86,
		0xb6, 0x0a, 0x89, 0x3e, 0x51, 0x2b, 0xdb, 0x98,
		0xbe, 0xa0, 0xb8, 0x46, 0x2a, 0x72, 0x97, 0x5d,
		0xc7, 0xd8, 0x3b, 0x29, 0x40, 0x0f, 0xbd, 0xcb,
		0xcd, 0x17, 0xe3, 0x19, 0x35, 0x08, 0x5f, 0x2d,
		0x39, 0xa7, 0xc1, 0x7f, 0x67, 0x5a, 0x5a, 0x9d,
		0xeb, 0x67, 0x34, 0x39, 0x75, 0xe8, 0x26, 0x1d,
		0x33, 0x24, 0x73, 0xa5, 0xf8, 0xa0, 0x2a, 0xe8,
		0x9a, 0xf5, 0x72, 0x2b, 0xaf, 0x11, 0xeb, 0x1d,
		0x92, 0x05, 0x8a, 0xa8, 0xe6, 0x25, 0x51, 0x7c,
		0x4f, 0x8c, 0x32, 0x1d, 0xf2, 0xc0, 0xda, 0x8e,
		0xc3, 0x3b, 0x3e, 0xd7, 0xb4, 0xc3, 0x49, 0x56,
		0x4e, 0x60, 0x80, 0x0a, 0xe2, 0x36, 0x2b, 0x5f,
		0xb4, 0xe1, 0xa7, 0x12, 0xe2, 0xe0, 0x8b, 0x1e,
		0x24, 0x9f, 0xd3, 0x55, 0xd9, 0x5f, 0xcf, 0x7d,
		0xbf, 0xc8, 0x97, 0x24, 0x31, 0x65, 0xc0, 0xaf,
		0x62, 0x8f, 0x0d, 0x48, 0x6e, 0x4a, 0xbd, 0xd1,
		0x21, 0x4b, 0x39, 0xf7, 0x8f, 0x4a, 0xfe, 0x2a,
		0xf0, 0x28, 0x01, 0xe5, 0xde, 0xfd, 0x8f, 0x2c,
		0x43, 0xe9, 0x7e, 0xe5, 0x17, 0x50, 0xbf, 0x20,
		0xee, 0x7e, 0xed, 0x3d, 0xf0, 0xa2, 0x98, 0x7e,
		0x21, 0xcf, 0x2b, 0xba, 0x44, 0x07, 0x80, 0x5a,
		0x6e, 0xa4, 0xfb, 0x58, 0xba, 0x30, 0x45, 0x9c,
		0x99, 0xa8, 0xb1, 0x65, 0x89, 0xfd, 0x61, 0xb8,
		0xe0, 0x4b, 0x74, 0x8b, 0xe2, 0x07, 0x9a, 0x2b,
		0xdf, 0xbb, 0xcd, 0x00, 0xa2, 0xa2, 0x94, 0x07,
		0x3a, 0x40, 0x9a, 0x18, 0x05, 0x87, 0x53, 0x9a,
		0x02, 0x8f, 0x2a, 0xaf, 0x79, 0xe2, 0xe3, 0x90,
		0xf5, 0x02, 0xd7, 0xed, 0xe3, 0x4a, 0x9e, 0x00,
		0x62, 0x22, 0x60, 0x4d, 0x27, 0xb0, 0xb2, 0x4d,
		0x6a, 0x40, 0xc8, 0x99, 0x49, 0xb8, 0x76, 0x94,
		0xb3, 0x67, 0x4b, 0x2c, 0xfa, 0xdc, 0x49, 0x5c,
		0x29, 0x62, 0xed, 0xa3, 0xfe, 0xfe, 0x95, 0xcc,
		0x3e, 0xce, 0x59, 0xae, 0x31, 0xcb, 0xa5, 0x05,
		0x45, 0x29, 0x58, 0x04, 0x92, 0xf4, 0x66, 0x20,
		0x3b, 0xf8, 0x18, 0xca, 0xd5, 0x41, 0x2e, 0xb2,
		0xd6, 0x61, 0xae, 0xd3, 0x75, 0xc5, 0xa2, 0x1b,
		0x7b, 0x2a, 0xbc, 0x71, 0x65, 0x15, 0x23, 0x48,
		0xba, 0xe8, 0xde, 0x3b, 0x4c, 0xe2, 0x8c, 0xab,
		0x74, 0xa1, 0x46, 0xbb, 0x44, 0x21, 0x15, 0x93,
		0xda, 0x01, 0x6b, 0xbe, 0xd8, 0x7c, 0xe4, 0xfd,
		0x91, 0x60, 0x9a, 0xbb, 0x29, 0xd7, 0x07, 0x3a,
		0xfc, 0xf3, 0xf6, 0x3a, 0x55, 0x7e, 0xcf, 0x1d,
		0xcc, 0xbc, 0x92, 0xeb, 0x14, 0xfb, 0x28, 0x19,
		0xae, 0xd5, 0x66, 0x5b, 0x62, 0xc9, 0xd6, 0xe2,
		0x9b, 0x62, 0xfa, 0x85, 0x71, 0xcb, 0x73, 0xab,
		0x48, 0xf3, 0x03, 0x9d, 0xe9, 0x09, 0x3e, 0xe0,
		0x80, 0xcb, 0x0f, 0x63, 0xa7, 0x86, 0x12, 0x84,
		0xab, 0xb5, 0xae, 0x44, 0xf6, 0x8f, 0xef, 0x8b,
		0xad, 0x18, 0x17, 0xaf, 0xd1, 0xbf, 0x66, 0x39,
		0x3e, 0x49, 0x87, 0x9a, 0x72, 0x02, 0xa1, 0xad,
		0xc1, 0xf8, 0xb6, 0xe3, 0x2b, 0x54, 0x5c, 0xbc,
		0x99, 0xd5, 0xde, 0xa3, 0x6e, 0x0c, 0x23, 0xd4,
		0x69, 0x1a, 0x5c, 0x75, 0x9b, 0xa2, 0xcb, 0xe7,
		0x4a, 0xab, 0x26, 0xfd, 0x54, 0x32, 0x81, 0xd6,
		0xba, 0xe1, 0x34, 0x62, 0x15, 0x4e, 0xd5, 0x25,
		0xed, 0x51, 0x82, 0x86, 0x76, 0x03, 0x0a, 0x9a,
		0xb8, 0x5b, 0xa1, 0x04, 0x83, 0x52, 0x34, 0x5c,
		0xb1, 0x86, 0xf2, 0x63, 0x59, 0x33, 0x59, 0x16,
		0x00, 0xe4, 0xa9, 0x62, 0x94, 0x7f, 0xa1, 0x56,
		0x64, 0x3d, 0x3e, 0x2b, 0x74, 0x47, 0xba, 0xe6,
		0xc2, 0x27, 0x84, 0xbc, 0x47, 0x1c, 0xc1, 0x5e,
		0xed, 0x43, 0x37, 0xcf, 0x39, 0xb4, 0x6b, 0x0b,
		0xbd, 0x3a, 0x54, 0x04, 0xa4, 0x00, 0x26, 0x7b,
		0xd6, 0x4b, 0x58, 0x20, 0xe9, 0x63, 0x3d, 0x8c,
		0x6b, 0x50, 0xf3, 0xbc, 0xd6, 0x14, 0x3e, 0xc3,
		0xd5, 0x85, 0xa9, 0xbf, 0xad, 0xc0, 0xb7, 0xf5,
		0xd0, 0x77, 0x7b, 0xd5, 0x50, 0x12, 0x25, 0xe0,
		0x46, 0xc2, 0x91, 0x35, 0x7b, 0x82, 0x3e, 0xc3,
		0xb3, 0xf0, 0x5c, 0x70, 0x7f, 0x53, 0x72, 0x2c,
		0x73, 0x0e, 0xef, 0x31, 0x4a, 0x6e, 0xae, 0x56,
		0x24, 0x59, 0x69, 0x39, 0x13, 0x29, 0xb0, 0xb4,
		0x3f, 0xf1, 0x16, 0x10, 0xc5, 0x2f, 0x35, 0x64,
		0x1b, 0xee, 0x4c, 0xbf, 0x88, 0x30, 0x51, 0x29,
		0xfa, 0xa9, 0xab, 0x36, 0x44, 0x8c, 0x88, 0xdf,
		0xfa, 0x2d, 0x14, 0x35, 0xd4, 0x90, 0x3e, 0x10,
		0x62, 0xfd, 0xec, 0xcc, 0x3c, 0xcb, 0xdf, 0x8c,
		0x97, 0x15, 0x78, 0x37, 0xe1, 0x43, 0x0a, 0xcc,
		0x43, 0x25, 0xca, 0x29, 0x32, 0xfd, 0xf2, 0x0d,
		0xa7, 0xf2, 0xc8, 0x37, 0x3f, 0x9a, 0x0e, 0x59,
		0xa3, 0x14, 0xf8, 0x06, 0xef, 0xcb, 0xea, 0xb2,
		0x2e, 0xc1, 0x15, 0xb5, 0x43, 0x92, 0x3d, 0xe4,
		0x8d, 0xa9, 0x01, 0x14, 0x9d, 0xe1, 0x60, 0x59,
		0xb9, 0x5e, 0x1d, 0x93, 0xec, 0x83, 0x81, 0x37,
		0x22, 0xb1, 0x50, 0x8a, 0x0a, 0x19, 0xaf, 0xad,
		0x52, 0xc9, 0xc8, 0x35, 0x74, 0xb6, 0x9e, 0x36,
		0xa4, 0x82, 0x3d, 0x2b, 0x62, 0xa0, 0x1b, 0xf6,
		0xbd, 0x40, 0xfb, 0x1f, 0x10, 0x0b, 0x80, 0x58,
		0x93, 0xb9, 0x1e, 0x44, 0xa5, 0xed, 0x86, 0x77,
		0x91, 0x82, 0x29, 0x67, 0x11, 0x61, 0x91, 0x42,
		0x16, 0x16, 0x8c, 0xf2, 0x1f, 0x16, 0x0c, 0xe7,
		0xbf, 0xfc, 0x50, 0xda, 0x2c, 0x29, 0x60, 0x6a,
		0x01, 0xf4, 0x35, 0x5c, 0xc8, 0xe0, 0x0d, 0x59,
		0xb0, 0x47, 0x01, 0xee, 0xb6, 0xcc, 0xb0, 0xc5,
		0xa8, 0x9b, 0x81, 0xd6, 0x9b, 0xc9, 0xf8, 0xb4,
		0x1b, 0x01, 0xd9, 0x2d, 0xa7, 0x74, 0x83, 0x44,
		0x48, 0x29, 0x83, 0xe6, 0xdc, 0x8d, 0xc7, 0xb1,
		0x8f, 0xac, 0xcf, 0xad, 0x51, 0xa1, 0x64, 0xb0,
		0xf9, 0x4d, 0xe1, 0x09, 0x0d, 0x6f, 0x46, 0x6c,
		0x0f, 0x99, 0x59, 0x6c, 0xda, 0x2c, 0x12, 0x21,
		0xb8, 0xa6, 0x19, 0xde, 0x16, 0x1b, 0x6a, 0x65,
		0xba, 0x54, 0x48, 0x61, 0x94, 0xac, 0x67, 0xab,
		0xf7, 0x74, 0x26, 0x4f, 0xde, 0xb4, 0xc0, 0x1b,
		0x0c, 0xc3, 0x46, 0x8c, 0xf4, 0x82, 0x68, 0xcb,
	}

	testRatchetCipherCipherTextBytes = []byte{
		0xD9, 0xDC, 0x9D, 0x6D, 0xED, 0xDA, 0x7B, 0x15,
		0x7A, 0x8C, 0x16, 0x9B, 0x25, 0x20, 0x52, 0x56,
		0x41, 0x5F, 0x52, 0xFD, 0x6E, 0x75, 0x21, 0x1F,
		0x76, 0x73, 0xE0, 0xB4, 0xAD, 0xEB, 0x9E, 0xAD,
		0xC3, 0xEB, 0x71, 0xBE, 0x79, 0xDA, 0x15, 0x89,
		0xEE, 0x61, 0xEE, 0x5D, 0x90, 0x3A, 0x0E, 0x53,
		0xF1, 0xD7, 0x2C, 0xAE, 0xD0, 0x43, 0x6F, 0xCE,
		0xCB, 0x1E, 0x62, 0xA2, 0x34, 0x91, 0xB9, 0xD8,
		0xB2, 0xD6, 0xE6, 0x84, 0x1A, 0xA4, 0xCF, 0x46,
		0x5D, 0xE0, 0x1E, 0xD0, 0x0E, 0x43, 0xB5, 0xB8,
		0x60, 0x37, 0x59, 0xD0, 0xAF, 0x77, 0xD4, 0x2A,
		0x3B, 0x69, 0xDF, 0xE6, 0x14, 0x69, 0xC1, 0xC1,
		0x02, 0x59, 0x09, 0x50, 0xBB, 0x00, 0x73, 0x7C,
		0x58, 0xC6, 0x49, 0xD8, 0x73, 0x88, 0xE7, 0x9C,
		0xBB, 0x95, 0xFD, 0x99, 0xA6, 0x78, 0x0A, 0xE3,
		0x88, 0xBC, 0x7E, 0xD2, 0xA6, 0x71, 0xFE, 0xF5,
		0x42, 0xF3, 0x66, 0x25, 0xCB, 0x3B, 0x5A, 0xB8,
		0x60, 0xBD, 0x13, 0xA9, 0xDD, 0xA7, 0x0F, 0x83,
		0xAD, 0xF2, 0xAE, 0x16, 0x05, 0x4C, 0xF6, 0x24,
		0x32, 0x53, 0xB3, 0x74, 0x58, 0xFF, 0xFB, 0xFB,
		0x09, 0xB6, 0x79, 0x12, 0x4C, 0xDB, 0xA5, 0x78,
		0xD8, 0xDB, 0xED, 0x30, 0x22, 0x79, 0xEC, 0x6A,
		0x7D, 0x4E, 0xBE, 0x09, 0xFC, 0xD7, 0x39, 0xA0,
		0xA7, 0x86, 0xB1, 0x58, 0x91, 0x38, 0x7B, 0xC7,
		0x16, 0xA1, 0xBB, 0x38, 0x9D, 0xB2, 0x20, 0xFE,
		0x07, 0x2F, 0xD6, 0x3E, 0x93, 0x6D, 0xD7, 0xD2,
		0x10, 0xBC, 0x4C, 0x41, 0xE4, 0xA6, 0x7A, 0x3D,
		0xEF, 0x25, 0xD1, 0xD9, 0x06, 0xC5, 0x5C, 0x11,
		0x54, 0xBA, 0xA2, 0xB7, 0x38, 0x46, 0xBF, 0x4C,
		0x46, 0x60, 0x5F, 0x5D, 0xAC, 0x7D, 0x2D, 0x98,
		0xE7, 0xED, 0x3D, 0xEF, 0x85, 0x5C, 0xAE, 0xC3,
		0xFD, 0xAB, 0x1A, 0xDC, 0x88, 0x23, 0xF7, 0x5E,
		0x24, 0x6E, 0x66, 0xE1, 0x3D, 0x29, 0x1D, 0xFE,
		0x9A, 0x1A, 0x1F, 0xF2, 0x4A, 0x72, 0xDC, 0xD8,
		0x74, 0x08, 0xAB, 0x3D, 0x8B, 0xBF, 0x38, 0x6E,
		0x2D, 0x2B, 0x3E, 0xD7, 0x55, 0xE0, 0xCC, 0xBD,
		0x17, 0x50, 0x5B, 0xA8, 0xB4, 0xE2, 0x43, 0xB3,
		0x01, 0x63, 0x83, 0x82, 0xC9, 0x14, 0x33, 0x84,
		0x1C, 0xDD, 0xD8, 0x7E, 0xC2, 0xBA, 0xA0, 0x6F,
		0xE6, 0xDA, 0xB2, 0xF3, 0x41, 0x40, 0x65, 0xC7,
		0xD7, 0x2F, 0x56, 0x83, 0x5B, 0xF0, 0x91, 0xD5,
		0x21, 0x5A, 0xEC, 0xEC, 0x17, 0x52, 0xD9, 0x6E,
		0x2D, 0x03, 0x7F, 0x70, 0x5F, 0x0B, 0x31, 0x5F,
		0xCD, 0xC1, 0x40, 0x96, 0x1C, 0x9C, 0x60, 0x65,
		0x53, 0x01, 0x31, 0x53, 0xAF, 0x1E, 0xBC, 0x08,
		0xC1, 0xEF, 0x14, 0xA8, 0x75, 0xA9, 0xF1, 0x23,
		0x74, 0x4A, 0x10, 0x3F, 0x89, 0x74, 0x15, 0x6B,
		0x15, 0xCC, 0x7B, 0x4F, 0xB6, 0xCD, 0xE1, 0xDB,
		0x3C, 0x01, 0x3D, 0x83, 0x8D, 0x98, 0xAA, 0x74,
		0x3E, 0xE3, 0xD1, 0x85, 0x89, 0xC5, 0xF7, 0xCC,
		0x10, 0xFA, 0x5C, 0x34, 0x8F, 0xFF, 0xC2, 0x3B,
		0xB6, 0xBE, 0x51, 0x78, 0x62, 0x45, 0x99, 0xD6,
		0x24, 0x43, 0x3A, 0xA9, 0x97, 0xD6, 0xDF, 0x5D,
		0xBB, 0x9B, 0x7F, 0x74, 0xB2, 0x82, 0xA0, 0x8A,
		0xA5, 0x57, 0x02, 0xAE, 0x40, 0x60, 0x87, 0x5C,
		0xC0, 0x23, 0xF4, 0x5B, 0x86, 0x4F, 0xF2, 0x16,
		0x91, 0x96, 0x02, 0x7D, 0xC8, 0x37, 0x13, 0x16,
		0xDA, 0xDA, 0x1A, 0x55, 0x2A, 0x17, 0x22, 0x6D,
		0xFC, 0xA2, 0xE5, 0x97, 0xAF, 0x00, 0xE7, 0x8A,
		0xA9, 0xE0, 0x1F, 0x41, 0xAA, 0x8B, 0xB9, 0x51,
		0x03, 0xDF, 0x87, 0xC9, 0x04, 0x56, 0xD0, 0x4A,
		0x40, 0xAA, 0x05, 0x46, 0xAE, 0x31, 0x95, 0x4E,
		0x5D, 0xB8, 0x53, 0x1F, 0xF3, 0x18, 0x30, 0x42,
		0x88, 0xB1, 0x63, 0x97, 0xD6, 0x3A, 0x3E, 0xDB,
		0x15, 0x69, 0xE5, 0xBE, 0x9F, 0xAE, 0x3C, 0x7E,
		0xE1, 0xD8, 0xF0, 0xAA, 0x69, 0x75, 0x9B, 0x16,
		0x63, 0xFA, 0xCC, 0xA1, 0xF6, 0x69, 0x4D, 0xEF,
		0xB9, 0x90, 0x6B, 0x2A, 0xD5, 0xF5, 0x19, 0x41,
		0x3B, 0x28, 0x1B, 0xF6, 0x8A, 0xC7, 0xB0, 0xE9,
		0x6E, 0x03, 0x8B, 0xAB, 0x30, 0x75, 0x21, 0xEF,
		0xFF, 0xB6, 0xE6, 0xCF, 0x3F, 0x13, 0x77, 0x9A,
		0x4B, 0x23, 0xB6, 0xCF, 0xC0, 0x67, 0x46, 0x2C,
		0x43, 0x19, 0x24, 0xB4, 0xFE, 0x86, 0x72, 0x9B,
		0x89, 0x6C, 0x08, 0x41, 0x93, 0xC2, 0xE7, 0xA7,
		0xED, 0x82, 0x29, 0xA3, 0x8C, 0x31, 0x87, 0x80,
		0x41, 0xE3, 0x49, 0x14, 0x0A, 0xA4, 0x73, 0x7F,
		0x5B, 0x5D, 0x61, 0x34, 0xC4, 0x99, 0xBD, 0xB9,
		0x6A, 0x9B, 0xCE, 0x74, 0x61, 0xD7, 0x25, 0x4E,
		0xBA, 0x51, 0xB0, 0x16, 0x2E, 0x70, 0xF9, 0x3D,
		0x89, 0xB9, 0x7B, 0x24, 0x33, 0x9F, 0xEF, 0x08,
		0xBD, 0x4C, 0x92, 0x88, 0xCB, 0x2B, 0xC1, 0xD5,
		0x50, 0x42, 0xA9, 0xCA, 0x31, 0x19, 0x3F, 0x13,
		0x1A, 0x89, 0xF3, 0xB6, 0xF2, 0xDF, 0xCE, 0x28,
		0x84, 0xB2, 0x85, 0x63, 0xBE, 0x54, 0xE0, 0x20,
		0x8E, 0x54, 0x10, 0xE9, 0x53, 0x8D, 0x9D, 0x9C,
		0x0F, 0x90, 0xB6, 0xAE, 0xF3, 0x8C, 0x50, 0x84,
		0x3B, 0x89, 0x06, 0x4E, 0xBA, 0x6C, 0x65, 0x1A,
		0x04, 0xF0, 0x76, 0x4C, 0xE7, 0xD3, 0x2D, 0x66,
		0x1A, 0xE3, 0xB1, 0x29, 0xF8, 0x6D, 0x7B, 0x3A,
		0x8C, 0xD8, 0x07, 0x53, 0x16, 0x49, 0x9F, 0xD4,
		0xD8, 0x55, 0x12, 0x6D, 0x33, 0x85, 0x5B, 0x97,
		0x6F, 0x07, 0xE0, 0x16, 0xD5, 0x99, 0x7E, 0xB8,
		0x87, 0xFB, 0xA5, 0x5C, 0x9D, 0xB7, 0x45, 0x27,
		0xA4, 0x36, 0x2F, 0xC8, 0xFC, 0x48, 0xF3, 0xE7,
		0x9E, 0x9A, 0x21, 0x7E, 0x68, 0x9C, 0xAE, 0xB2,
		0xC6, 0x28, 0xA9, 0xE3, 0xBD, 0x3E, 0xB3, 0x98,
		0x42, 0x27, 0x05, 0x4B, 0x20, 0x12, 0xCD, 0xF5,
		0x1A, 0x57, 0x71, 0x16, 0x09, 0x3C, 0xF1, 0xA4,
		0xD2, 0xDE, 0x9C, 0xEE, 0xF1, 0xA7, 0xF6, 0x30,
		0x2E, 0x54, 0xC3, 0x0D, 0xDC, 0x50, 0x11, 0x18,
		0xDA, 0x76, 0xDC, 0xA7, 0xB5, 0x66, 0x25, 0x69,
		0x08, 0xD9, 0xEB, 0xF0, 0xA5, 0xA1, 0x86, 0xF5,
		0xD2, 0x90, 0x55, 0x66, 0x37, 0x8B, 0x96, 0x74,
		0x16, 0xD1, 0x39, 0x20, 0xB6, 0x5B, 0x84, 0x9E,
		0x86, 0xBC, 0x0E, 0xB7, 0xFB, 0x41, 0x9E, 0x6A,
		0x7D, 0x19, 0x0A, 0xA7, 0x63, 0x40, 0x8D, 0x7B,
		0xD9, 0x37, 0x70, 0x47, 0x06, 0x7F, 0x78, 0x34,
		0xC1, 0x06, 0x30, 0xB1, 0x4B, 0x51, 0x3F, 0x85,
		0xF1, 0x2A, 0x5F, 0xCA, 0xD7, 0x63, 0x16, 0xB8,
		0x2B, 0x42, 0x7C, 0x48, 0x9E, 0x43, 0x6D, 0xCC,
		0xDF, 0xA6, 0xAF, 0xD8, 0xAF, 0x3E, 0x06, 0xD4,
		0x67, 0xB1, 0x6D, 0xC5, 0xE0, 0xB9, 0x8C, 0x38,
		0x2F, 0x78, 0x9F, 0x08, 0xB3, 0x9B, 0xAD, 0x66,
		0xBE, 0xBF, 0xF8, 0x47, 0xDF, 0x47, 0x91, 0x7E,
		0xCE, 0x03, 0xBD, 0xA6, 0x63, 0x21, 0x46, 0x4D,
		0xBB, 0x1C, 0x8F, 0x19, 0x93, 0x09, 0xB2, 0xDD,
		0x50, 0xF2, 0x1E, 0xB8, 0x6A, 0xBF, 0x05, 0x3B,
		0x09, 0xBE, 0x6E, 0xD0, 0xB0, 0xC9, 0x81, 0x70,
		0x29, 0xF3, 0xA6, 0x1E, 0xD0, 0x00, 0xC0, 0x55,
		0xE2, 0x74, 0xE4, 0x4B, 0x6A, 0x17, 0x02, 0xC4,
		0xF9, 0xCB, 0x37, 0x64, 0x32, 0x9A, 0xDF, 0x2B,
		0x0B, 0xA0, 0xED, 0x98, 0xC8, 0x67, 0x3F, 0x00,
		0x34, 0xD7, 0x4D, 0x6A, 0xCF, 0x03, 0xFF, 0x26,
		0x5C, 0xBE, 0x80, 0x09, 0x01, 0xDA, 0x1F, 0x62,
		0x6A, 0x5E, 0x4B, 0x0F, 0x1F, 0xC0, 0xF2, 0x77,
		0xCD, 0xA0, 0x39, 0xA1, 0xD3, 0x47, 0x67, 0x98,
		0xEB, 0x6F, 0x04, 0xB4, 0x93, 0xD7, 0x33, 0x2A,
		0xD8, 0xC7, 0xDA, 0x84, 0xA5, 0x9F, 0xE9, 0x96,
		0xED, 0x52, 0xC2, 0x0E, 0x5B, 0xCA, 0x32, 0x6B,
		0x41, 0x0C, 0x38, 0xC1, 0x5A, 0x5D, 0x5C, 0x6C,
	}
)

func TestCipherVector(t *testing.T) {
	ciphertext, err := Encrypt(testRatchetCipherKeyBytes, testRatchetCipherPlainTextBytes)
	require.NoError(t, err)
	require.Equal(t, testRatchetCipherCipherTextBytes, ciphertext)
}
