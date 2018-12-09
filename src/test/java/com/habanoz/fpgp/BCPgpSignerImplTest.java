package com.habanoz.fpgp;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class BCPgpSignerImplTest {
	File signerPrivateFile = new File("test/cert/0xED98F60D-sec.asc");
	File signerPublicFile = new File("test/cert/0xED98F60D-pub.asc");
	String signerPass = "145145145";

	File receiverPrivateFile = new File("test/cert/0x46CD6A4B-sec.asc");
	File receiverPublicFile = new File("test/cert/0x46CD6A4B-pub.asc");
	String receiverPass = "123456";

	@Test
	public void testSignEncryptAndDecryptVerify() throws Exception {
		Assert.assertTrue(testSign());
		Assert.assertTrue(testDecryptSigned());
	}

	public boolean testSign() throws Exception {


		File inputFile = new File("test/input/test.txt");
		File signedFile = new File("test/work/test_signed.pgp");

		IPgpSigner pgpSigner = PgpSignerFactory.getPgpSigner(signerPublicFile, signerPrivateFile, signerPass, receiverPublicFile, receiverPrivateFile, receiverPass);
		return pgpSigner.sign(inputFile, signedFile);
	}

	public boolean testDecryptSigned() throws Exception {

		File signedFile = new File("test/work/test_signed.pgp");
		File decryptedFile = new File("test/work/decrypted.txt");

		IPgpSigner pgpSigner = PgpSignerFactory.getPgpSigner(signerPublicFile, signerPrivateFile, signerPass, receiverPublicFile, receiverPrivateFile, receiverPass);
		return pgpSigner.decryptSigned(signedFile,decryptedFile);
	}
}
