package com.habanoz.fpgp;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BCPgpSignerImpl implements IPgpSigner {
	private static final Logger logger = LoggerFactory.getLogger(BCPgpSignerImpl.class);

	private PGPFileProcessor pgpFileProcessor;

	public BCPgpSignerImpl(PGPFileProcessor pgpFileProcessor) {
		this.pgpFileProcessor = pgpFileProcessor;
	}

	public boolean sign(File file, File signedFile) throws SigninException {
		try {
			return pgpFileProcessor.signEncrypt(file, signedFile);
		} catch (Exception e) {
			logger.error("Error while signing file '{}'", file.getName(), e);
			throw new SigninException(e);
		}
	}

	public boolean decryptSigned(File signedFile, File decryptedFile) throws SigninException {
		try {
			return pgpFileProcessor.decryptSigned(signedFile, decryptedFile);
		} catch (Exception e) {
			logger.error("Error while signing file '{}'", signedFile.getName(), e);
			throw new SigninException(e);
		}
	}
}
