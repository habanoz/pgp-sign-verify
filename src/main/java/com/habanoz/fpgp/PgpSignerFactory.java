package com.habanoz.fpgp;

import java.io.File;

public class PgpSignerFactory {
	public static IPgpSigner getPgpSigner(File signerPublicKeyFile, File signerSecretKeyFile, String signerPass, File decryptorPublicKeyFile, File decryptorSecretKeyFile, String decryptorPass) {
		PGPFileProcessor pgpFileProcessor = new PGPFileProcessor(signerPublicKeyFile, signerSecretKeyFile, signerPass, decryptorPublicKeyFile, decryptorSecretKeyFile, decryptorPass);
		return new BCPgpSignerImpl(pgpFileProcessor);
	}
}
