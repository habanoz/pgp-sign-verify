package com.habanoz.fpgp;

import java.io.File;

public interface IPgpSigner {
	boolean sign(File file, File signedFile) throws Exception;
	boolean decryptSigned(File signedFile, File decryptedFile) throws Exception;
}
