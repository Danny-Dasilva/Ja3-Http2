spec := utls.ClientHelloSpec{
	TLSVersMax: utls.VersionTLS13,
	TLSVersMin: utls.VersionTLS10,
	CipherSuites: []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_AES_128_GCM_SHA256, // utls 1.3
		utls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
		&utls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.ECDSAWithP521AndSHA512,
			utls.PSSWithSHA256,
			utls.PSSWithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA256,
			utls.PKCS1WithSHA384,
			utls.PKCS1WithSHA512,
			utls.ECDSAWithSHA1,
			utls.PKCS1WithSHA1}},
		&utls.KeyShareExtension{[]utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519},
		}},
		&utls.PSKKeyExchangeModesExtension{[]uint8{1}}, // pskModeDHE
		&utls.SupportedVersionsExtension{[]uint16{
			utls.VersionTLS13,
			utls.VersionTLS12,
			utls.VersionTLS11,
			utls.VersionTLS10}},
	},
	GetSessionID: nil,
}